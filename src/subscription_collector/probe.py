from __future__ import annotations

import asyncio
import json
import socket
import statistics
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx

from .models import ProbeResult, Profile
from .singbox_config import build_singbox_config


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    url: str
    expected_status: int


DEFAULT_PROBE_TARGETS = (
    ProbeTarget("https://www.gstatic.com/generate_204", 204),
    ProbeTarget("https://www.google.com/generate_204", 204),
    ProbeTarget("https://cp.cloudflare.com/generate_204", 204),
    ProbeTarget("https://www.apple.com/library/test/success.html", 200),
)


def evaluate_probe_statuses(
    statuses: Sequence[int | None],
    *,
    expected_statuses: Sequence[int],
    required_successes: int,
) -> int:
    """Count expected responses; the caller compares the count to the configured quorum."""
    if len(statuses) != len(expected_statuses):
        raise ValueError("statuses must align with expected statuses")
    if required_successes < 1 or required_successes > len(expected_statuses):
        raise ValueError("required_successes must be within probe count")
    return sum(
        actual == expected for actual, expected in zip(statuses, expected_statuses, strict=True)
    )


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


async def _request_target(
    client: httpx.AsyncClient,
    target: ProbeTarget,
    *,
    timeout_seconds: float,
) -> tuple[int | None, int | None, str | None]:
    """Request one control URL without exceeding its wall-clock response budget."""
    started = time.monotonic()
    try:
        response = await asyncio.wait_for(client.get(target.url), timeout=timeout_seconds)
    except (TimeoutError, httpx.TimeoutException):
        return None, None, "timeout"
    except httpx.HTTPError:
        return None, None, "http_error"
    elapsed = round((time.monotonic() - started) * 1000)
    return response.status_code, elapsed, None


def _error_category(errors: Sequence[str | None], successes: int) -> str | None:
    if successes:
        return None
    categories = sorted(error for error in errors if error)
    return categories[0] if categories else "unexpected_status"


async def probe_profile(
    profile: Profile,
    sing_box_path: Path,
    *,
    probe_targets: Sequence[ProbeTarget] = DEFAULT_PROBE_TARGETS,
    timeout_seconds: float = 0.3,
    startup_timeout_seconds: float = 3.0,
    required_successes: int = 2,
) -> ProbeResult:
    """Run exactly one temporary profile process and four concurrent redacted URL probes."""
    if len(probe_targets) != 4:
        raise ValueError("exactly four probe targets are required")
    if not sing_box_path.is_file():
        return ProbeResult(False, 0, None, "binary_unavailable")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if startup_timeout_seconds <= 0:
        raise ValueError("startup_timeout_seconds must be positive")

    port = _reserve_loopback_port()
    process: asyncio.subprocess.Process | None = None
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            temporary_path.chmod(0o600)
            json.dump(build_singbox_config(profile, port, "profile"), handle, separators=(",", ":"))
        process = await asyncio.create_subprocess_exec(
            str(sing_box_path),
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
            responses = await asyncio.gather(
                *(
                    _request_target(client, target, timeout_seconds=timeout_seconds)
                    for target in probe_targets
                )
            )
        statuses = [item[0] for item in responses]
        latencies = [item[1] for item in responses if item[1] is not None]
        errors = [item[2] for item in responses]
        successes = evaluate_probe_statuses(
            statuses,
            expected_statuses=tuple(target.expected_status for target in probe_targets),
            required_successes=required_successes,
        )
        median = round(statistics.median(latencies)) if latencies else None
        return ProbeResult(
            passed=successes >= required_successes,
            successes=successes,
            median_latency_ms=median,
            error_category=_error_category(errors, successes),
        )
    except TimeoutError:
        return ProbeResult(False, 0, None, "listener_timeout")
    except (OSError, ValueError):
        return ProbeResult(False, 0, None, "process_error")
    finally:
        if process is not None and process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            else:
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except TimeoutError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    else:
                        await process.wait()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
