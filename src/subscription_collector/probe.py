from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import tempfile
import time
from contextlib import suppress
from pathlib import Path

import httpx

from .models import ProbeResult, Profile
from .xray_config import build_xray_config

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
            await asyncio.sleep(0.05)
    raise TimeoutError("listener_timeout")


async def _run_config_test(xray_path: Path, config_path: Path, timeout_seconds: float) -> bool:
    process = await asyncio.create_subprocess_exec(
        str(xray_path),
        "run",
        "-test",
        "-c",
        str(config_path),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
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
        await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            return
        await process.wait()


async def probe_profile(
    profile: Profile,
    xray_path: Path,
    *,
    ip_echo_url: str = DEFAULT_IP_ECHO_URL,
    timeout_seconds: float = 3.0,
    startup_timeout_seconds: float = 5.0,
) -> ProbeResult:
    """Validate one profile by requesting a public IP through a transient local Xray proxy."""
    if not xray_path.is_file():
        return ProbeResult(False, 0, None, "binary_unavailable")
    if timeout_seconds <= 0 or startup_timeout_seconds <= 0:
        raise ValueError("probe timeouts must be positive")

    port = _reserve_loopback_port()
    process: asyncio.subprocess.Process | None = None
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            temporary_path.chmod(0o600)
            json.dump(build_xray_config(profile, port, "profile"), handle, separators=(",", ":"))

        if not await _run_config_test(xray_path, temporary_path, startup_timeout_seconds):
            return ProbeResult(False, 0, None, "config_invalid")

        process = await asyncio.create_subprocess_exec(
            str(xray_path),
            "run",
            "-c",
            str(temporary_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await _wait_for_listener(port, process, startup_timeout_seconds)
        proxy_url = f"socks5://127.0.0.1:{port}"
        timeout = httpx.Timeout(timeout_seconds)
        async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, trust_env=False) as client:
            latency_ms, error_category = await _request_public_ip(
                client, ip_echo_url, timeout_seconds
            )
        return ProbeResult(
            passed=error_category is None,
            successes=1 if error_category is None else 0,
            median_latency_ms=latency_ms,
            error_category=error_category,
        )
    except TimeoutError:
        return ProbeResult(False, 0, None, "listener_timeout")
    except (OSError, ValueError):
        return ProbeResult(False, 0, None, "process_error")
    finally:
        await _stop_process(process)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
