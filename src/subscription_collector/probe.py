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

from .config_loader import IpValidationConfig
from .models import ProbeResult, Profile
from .xray_config import build_xray_batch_config


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


async def _wait_for_listener(
    port: int,
    process: asyncio.subprocess.Process,
    timeout_seconds: float,
    poll_interval_seconds: float,
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
            await asyncio.sleep(poll_interval_seconds)
    raise TimeoutError("listener_timeout")


async def _wait_for_listeners(
    ports: Sequence[int], process: asyncio.subprocess.Process, settings: IpValidationConfig
) -> None:
    outcomes = await asyncio.gather(
        *(
            _wait_for_listener(
                port,
                process,
                settings.startup_timeout_seconds,
                settings.listener_poll_interval_seconds,
            )
            for port in ports
        ),
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


async def _request_http_status(
    client: httpx.AsyncClient,
    url: str,
    timeout_seconds: float,
    accepted_statuses: tuple[int, ...],
) -> tuple[int | None, str | None]:
    started_at = time.monotonic()
    try:
        response = await asyncio.wait_for(client.get(url), timeout=timeout_seconds)
    except (TimeoutError, httpx.TimeoutException):
        return None, "timeout"
    except httpx.HTTPError:
        return None, "http_error"
    latency_ms = round((time.monotonic() - started_at) * 1000)
    if response.status_code not in accepted_statuses:
        return latency_ms, "unexpected_status"
    return latency_ms, None


async def _probe_client(client: httpx.AsyncClient, settings: IpValidationConfig) -> ProbeResult:
    """Confirm a tunnel with IP echo first, then an independent HTTP response."""
    errors: list[str] = []
    for url in settings.ip_echo_urls:
        latency_ms, error_category = await _request_public_ip(client, url, settings.timeout_seconds)
        if error_category is None:
            return ProbeResult(True, 1, latency_ms)
        errors.append(f"ip_{error_category}")

    for url in settings.http_check_urls:
        latency_ms, error_category = await _request_http_status(
            client, url, settings.timeout_seconds, settings.accepted_http_statuses
        )
        if error_category is None:
            return ProbeResult(True, 1, latency_ms)
        errors.append(f"http_{error_category}")

    category = errors[0] if len(set(errors)) == 1 else "no_endpoint_confirmation"
    return ProbeResult(False, 0, None, category)


async def _stop_process(
    process: asyncio.subprocess.Process | None, shutdown_timeout_seconds: float
) -> None:
    if process is None or process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=shutdown_timeout_seconds)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            return
        await process.wait()


async def probe_batch(
    profiles: Sequence[Profile], xray_path: Path, *, settings: IpValidationConfig
) -> list[ProbeResult]:
    """Validate a batch through one temporary Xray process with isolated local ports."""
    profile_count = len(profiles)
    if profile_count == 0:
        return []
    if not xray_path.is_file():
        return _failed_results(profile_count, "binary_unavailable")

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

        if not await _run_config_test(
            xray_path, temporary_path, settings.config_test_timeout_seconds
        ):
            return _failed_results(profile_count, "config_invalid")

        process = await asyncio.create_subprocess_exec(
            str(xray_path),
            "run",
            "-c",
            str(temporary_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await _wait_for_listeners(ports, process, settings)
        semaphore = asyncio.Semaphore(settings.request_concurrency)

        async def probe_port(port: int) -> ProbeResult:
            async with semaphore:
                proxy_url = f"socks5://127.0.0.1:{port}"
                timeout = httpx.Timeout(settings.timeout_seconds)
                try:
                    async with httpx.AsyncClient(
                        proxy=proxy_url,
                        timeout=timeout,
                        trust_env=False,
                        limits=httpx.Limits(
                            max_connections=settings.connection_max_connections,
                            max_keepalive_connections=settings.connection_max_keepalive_connections,
                        ),
                    ) as client:
                        return await _probe_client(client, settings)
                except (OSError, ValueError):
                    return ProbeResult(False, 0, None, "http_error")

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
        await _stop_process(process, settings.process_shutdown_timeout_seconds)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


async def probe_profile(
    profile: Profile, xray_path: Path, *, settings: IpValidationConfig
) -> ProbeResult:
    """Validate one profile through the batch implementation for backwards compatibility."""
    return (await probe_batch([profile], xray_path, settings=settings))[0]
