from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import tempfile
import time
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

import httpx

from .models import ProbeResult, Profile, Protocol
from .xray_config import build_xray_batch_config

DEFAULT_IP_ECHO_URL = "https://api.ipify.org"


def is_public_ip_response(body: str) -> bool:
    """Accept only a single globally routable IP literal from the IP-echo service."""
    try:
        return ipaddress.ip_address(body.strip()).is_global
    except ValueError:
        return False


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _reserve_loopback_ports(count: int) -> list[int]:
    if count < 1:
        raise ValueError("port_count_must_be_positive")
    ports: set[int] = set()
    while len(ports) < count:
        ports.add(_reserve_loopback_port())
    return list(ports)


def _failed_results(count: int, category: str) -> list[ProbeResult]:
    return [ProbeResult(False, 0, None, category) for _ in range(count)]


def _exception_category(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) and str(exc) == "process_exited":
        return "process_exited"
    if isinstance(exc, TimeoutError):
        return "listener_timeout"
    if isinstance(exc, (OSError, ValueError)):
        return "process_error"
    return "probe_error"


async def tcp_precheck(profile: Profile, *, timeout_seconds: float) -> str | None:
    """Return a fail-closed category for unreachable TCP profiles; skip QUIC-based Hysteria2."""
    if profile.protocol is Protocol.HYSTERIA2:
        return None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(profile.server, profile.port), timeout=timeout_seconds
        )
    except (TimeoutError, OSError):
        return "tcp_unreachable"
    writer.close()
    await writer.wait_closed()
    return None


async def _wait_for_listener(
    port: int, process: asyncio.subprocess.Process, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.returncode is not None:
            raise RuntimeError("process_exited")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            del reader
            return
        except OSError:
            await asyncio.sleep(0.02)
    raise TimeoutError("listener_timeout")


async def _wait_for_listeners(
    ports: Sequence[int], process: asyncio.subprocess.Process, timeout_seconds: float
) -> None:
    outcomes = await asyncio.gather(
        *(_wait_for_listener(port, process, timeout_seconds) for port in ports),
        return_exceptions=True,
    )
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            raise outcome


async def _run_config_test(xray_path: Path, config_path: Path, timeout_seconds: float) -> bool:
    try:
        process = await asyncio.create_subprocess_exec(
            str(xray_path),
            "run",
            "-test",
            "-c",
            str(config_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return False
    try:
        return await asyncio.wait_for(process.wait(), timeout=timeout_seconds) == 0
    except TimeoutError:
        with suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        return False


async def _request_public_ip(
    client: httpx.AsyncClient, url: str, timeout_seconds: float
) -> tuple[int | None, str | None]:
    started_at = time.monotonic()
    try:
        response = await asyncio.wait_for(client.get(url), timeout=timeout_seconds)
    except (TimeoutError, httpx.TimeoutException):
        return None, "timeout"
    except httpx.HTTPError:
        return None, "http_error"
    latency_ms = round((time.monotonic() - started_at) * 1000)
    if response.status_code != 200:
        return latency_ms, "unexpected_status"
    if not is_public_ip_response(response.text):
        return latency_ms, "invalid_ip_response"
    return latency_ms, None


async def _stop_process(process: asyncio.subprocess.Process | None) -> None:
    if process is None or process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=0.2)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            return
        await process.wait()


async def probe_batch(
    profiles: Sequence[Profile],
    xray_path: Path,
    *,
    ip_echo_url: str = DEFAULT_IP_ECHO_URL,
    timeout_seconds: float = 0.75,
    startup_timeout_seconds: float = 1.0,
    request_concurrency: int = 64,
) -> list[ProbeResult]:
    """Validate a batch through one temporary Xray process with isolated local ports."""
    profile_count = len(profiles)
    if profile_count == 0:
        return []
    if not xray_path.is_file():
        return _failed_results(profile_count, "binary_unavailable")
    if timeout_seconds <= 0 or startup_timeout_seconds <= 0 or request_concurrency < 1:
        raise ValueError("probe_limits_must_be_positive")

    process: asyncio.subprocess.Process | None = None
    temporary_path: Path | None = None
    try:
        ports = _reserve_loopback_ports(profile_count)
        config = build_xray_batch_config(profiles, ports)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            temporary_path.chmod(0o600)
            json.dump(config, handle, separators=(",", ":"))

        if not await _run_config_test(xray_path, temporary_path, startup_timeout_seconds):
            return _failed_results(profile_count, "config_invalid")

        process = await asyncio.create_subprocess_exec(
            str(xray_path),
            "run",
            "-c",
            str(temporary_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await _wait_for_listeners(ports, process, startup_timeout_seconds)
        semaphore = asyncio.Semaphore(request_concurrency)

        async def probe_port(port: int) -> ProbeResult:
            async with semaphore:
                proxy_url = f"socks5://127.0.0.1:{port}"
                timeout = httpx.Timeout(timeout_seconds)
                try:
                    async with httpx.AsyncClient(
                        proxy=proxy_url,
                        timeout=timeout,
                        trust_env=False,
                        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                    ) as client:
                        latency_ms, error_category = await _request_public_ip(
                            client, ip_echo_url, timeout_seconds
                        )
                except (OSError, ValueError):
                    return ProbeResult(False, 0, None, "http_error")
                return ProbeResult(
                    passed=error_category is None,
                    successes=1 if error_category is None else 0,
                    median_latency_ms=latency_ms,
                    error_category=error_category,
                )

        outcomes = await asyncio.gather(
            *(probe_port(port) for port in ports), return_exceptions=True
        )
        results: list[ProbeResult] = []
        for outcome in outcomes:
            if isinstance(outcome, ProbeResult):
                results.append(outcome)
            elif isinstance(outcome, BaseException):
                results.append(ProbeResult(False, 0, None, _exception_category(outcome)))
            else:
                results.append(ProbeResult(False, 0, None, "probe_error"))
        return results
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
            raise
        return _failed_results(profile_count, _exception_category(exc))
    finally:
        await _stop_process(process)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


async def probe_profile(
    profile: Profile,
    xray_path: Path,
    *,
    ip_echo_url: str = DEFAULT_IP_ECHO_URL,
    timeout_seconds: float = 0.75,
    startup_timeout_seconds: float = 1.0,
) -> ProbeResult:
    """Validate one profile through the batch implementation for backwards compatibility."""
    return (
        await probe_batch(
            [profile],
            xray_path,
            ip_echo_url=ip_echo_url,
            timeout_seconds=timeout_seconds,
            startup_timeout_seconds=startup_timeout_seconds,
            request_concurrency=1,
        )
    )[0]
