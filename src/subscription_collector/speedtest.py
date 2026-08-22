"""Deep tunnel throughput measurement for proxy profiles.

The probe speaks the minimal client side of VLESS and Trojan, relays to a public
bulk-download endpoint through the profile's own tunnel, and analyses the
transfer instead of taking a single noisy sample: an initial warm-up window
absorbs TCP slow-start, then the measurement window is split into several
sub-windows whose per-window speeds yield the mean, peak, jitter and a
stability ratio. A composite quality score (0-100) combines speed, stability
and the endpoint latency measured by the reachability stage, and maps to
letter grades A-D. Protocol combinations that require a dedicated client core
(Hysteria2 over QUIC, VLESS over Reality or gRPC) are reported as
``speed_unsupported`` so callers can apply their own policy instead of guessing.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import os
import socket
import ssl
import statistics
import struct
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from time import perf_counter
from urllib.parse import urlsplit

from .config_loader import SpeedTestConfig
from .models import Profile

_EVIDENCE_BYTES = 262_144
_WS_BINARY_FRAME = 0x82
_WS_CLOSE = 0x8
_WS_PING = 0x9
_WS_PONG = 0xA

_SPEED_WEIGHT = 0.6
_STABILITY_WEIGHT = 0.25
_LATENCY_WEIGHT = 0.15
_NEUTRAL_LATENCY_COMPONENT = 60.0

GRADE_A = "A"
GRADE_B = "B"
GRADE_C = "C"
GRADE_D = "D"


class _HandshakeError(ConnectionError):
    """The proxy server rejected or truncated a protocol handshake."""


class _UpstreamError(ConnectionError):
    """The bulk endpoint behind the tunnel answered unexpectedly."""


@dataclass(frozen=True, slots=True)
class SpeedOutcome:
    """Result of one deep throughput measurement.

    ``passed``/``kbps``/``reason`` keep their historical positional order;
    the remaining fields carry the windowed analysis.
    """

    passed: bool
    kbps: float | None = None
    reason: str | None = None
    kbps_peak: float | None = None
    window_kbps: tuple[float, ...] = ()
    jitter_kbps: float | None = None
    stability: float | None = None
    score: float | None = None
    grade: str = ""


def quality_score(
    mean_kbps: float | None,
    stability: float | None,
    latency_component: float | None,
    *,
    target_kbps: float,
) -> tuple[float, str]:
    """Combine speed, stability and a latency component into a 0-100 score and grade.

    ``latency_component`` is a 0-100 value produced by the reachability stage;
    ``None`` scores neutral so profiles without a probe are not punished.
    """
    speed_component = 0.0 if mean_kbps is None else min(mean_kbps / target_kbps, 1.0) * 100.0
    stability_component = (min(max(stability, 0.0), 1.0) if stability is not None else 0.0) * 100.0
    effective_latency = (
        _NEUTRAL_LATENCY_COMPONENT if latency_component is None else min(latency_component, 100.0)
    )
    score = round(
        _SPEED_WEIGHT * speed_component
        + _STABILITY_WEIGHT * stability_component
        + _LATENCY_WEIGHT * effective_latency,
        1,
    )
    if score >= 80.0:
        return score, GRADE_A
    if score >= 60.0:
        return score, GRADE_B
    if score >= 40.0:
        return score, GRADE_C
    return score, GRADE_D


def tunnel_supported(profile: Profile) -> bool:
    """Report whether this combination can be measured without a proxy core."""
    if profile.protocol.value == "trojan":
        return (
            bool(profile.secret)
            and profile.transport == "tcp"
            and profile.security
            in {
                "none",
                "tls",
            }
        )
    if profile.protocol.value == "vless":
        return (
            profile.username is not None
            and profile.transport in {"tcp", "ws"}
            and (profile.security in {"none", "tls"})
        )
    return False


def _target_address(host: str, port: int) -> bytes:
    """Encode host and port as the SOCKS-style address both protocols expect."""
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack(">H", port)
    if parsed.version == 4:
        return b"\x01" + parsed.packed + struct.pack(">H", port)
    return b"\x04" + parsed.packed + struct.pack(">H", port)


def _tls_context() -> ssl.SSLContext:
    """Create a permissive context: proxy endpoints rarely present valid certs."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _open_transport(
    profile: Profile, settings: SpeedTestConfig
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    server_hostname = None
    ssl_context = None
    if profile.security == "tls":
        ssl_context = _tls_context()
        try:
            ipaddress.ip_address(profile.server)
        except ValueError:
            server_hostname = profile.server.encode("idna").decode("ascii")
    return await asyncio.open_connection(
        profile.server,
        profile.port,
        ssl=ssl_context,
        server_hostname=server_hostname,
        limit=65_536,
    )


def _ws_frame(payload: bytes) -> bytes:
    """Encode one masked binary WebSocket frame from the client side."""
    header = bytearray([_WS_BINARY_FRAME])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65_536:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return bytes(header) + masked


async def _read_ws_frame(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    """Return the payload of the next data frame; ``b""`` on close or EOF."""
    while True:
        try:
            first, second = await reader.readexactly(2)
        except (asyncio.IncompleteReadError, ConnectionError):
            return b""
        opcode = first & 0x0F
        length = second & 0x7F
        try:
            if length == 126:
                length = struct.unpack(">H", await reader.readexactly(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", await reader.readexactly(8))[0]
            mask = await reader.readexactly(4) if second & 0x80 else b""
            payload = await reader.readexactly(length) if length else b""
        except (asyncio.IncompleteReadError, ConnectionError):
            return b""
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == _WS_CLOSE:
            return b""
        if opcode == _WS_PING:
            pong = bytearray([_WS_PONG])
            pong.append(0x80 | len(payload))
            mask = os.urandom(4)
            pong += mask
            pong += bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            writer.write(bytes(pong))
            await writer.drain()
            continue
        if opcode in {0x1, 0x2, 0x0}:
            return payload


class _Relay:
    """Byte-stream view over either a raw stream or a WebSocket connection."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        websocket: bool,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._websocket = websocket
        self._buffer = b""

    async def send(self, data: bytes) -> None:
        self._writer.write(_ws_frame(data) if self._websocket else data)
        await self._writer.drain()

    async def receive(self) -> bytes:
        if self._buffer:
            chunk, self._buffer = self._buffer, b""
            return chunk
        if self._websocket:
            return await _read_ws_frame(self._reader, self._writer)
        return await self._reader.read(65_536)

    def push_back(self, data: bytes) -> None:
        """Return already-read bytes to the front of the stream."""
        self._buffer = data + self._buffer

    async def aclose(self) -> None:
        self._writer.close()
        with contextlib.suppress(ConnectionError):
            await self._writer.wait_closed()


async def _websocket_upgrade(
    profile: Profile,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    path = profile.params.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    host_header = profile.params.get("host") or profile.server
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    writer.write(request.encode("utf-8"))
    await writer.drain()
    while True:
        line = await reader.readline()
        if not line:
            raise _HandshakeError("websocket upgrade failed")
        if line in {b"\r\n", b"\n"}:
            break


async def _open_relay(profile: Profile, settings: SpeedTestConfig) -> tuple[_Relay, str, int]:
    """Connect to the profile and prepare its tunnel toward the bulk endpoint."""
    parts = urlsplit(settings.download_url)
    inner_host = parts.hostname or ""
    inner_port = parts.port or 80
    address = _target_address(inner_host, inner_port)
    raw_reader, raw_writer = await _open_transport(profile, settings)
    try:
        websocket = False
        if profile.transport == "ws":
            await _websocket_upgrade(profile, raw_reader, raw_writer)
            websocket = True
        relay = _Relay(raw_reader, raw_writer, websocket)
        if profile.protocol.value == "vless":
            user_id = uuid.UUID(str(profile.username)).bytes
            request = b"\x00" + user_id + b"\x00\x01" + address
            await relay.send(request)
            header = b""
            while len(header) < 2:
                chunk = await relay.receive()
                if not chunk:
                    raise _HandshakeError("vless handshake rejected")
                header += chunk
            if header[0] != 0x00:
                raise _HandshakeError("vless handshake rejected")
            needed = 2 + header[1]
            while len(header) < needed:
                chunk = await relay.receive()
                if not chunk:
                    raise _HandshakeError("vless handshake truncated")
                header += chunk
            relay.push_back(header[needed:])
        else:
            secret = hashlib.sha224(str(profile.secret).encode("utf-8")).hexdigest()
            await relay.send(secret.encode("ascii") + b"\r\n\x01" + address + b"\r\n")
        return relay, inner_host, inner_port
    except BaseException:
        await _close_transport(raw_reader, raw_writer)
        raise


async def _close_transport(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(ConnectionError):
        await writer.wait_closed()


def _http_request(parts: urlsplit) -> bytes:
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    host_header = parts.hostname or ""
    if parts.port and parts.port != 80:
        host_header = f"{host_header}:{parts.port}"
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode()


async def measure_profile(
    profile: Profile,
    settings: SpeedTestConfig,
    latency_component: float | None = None,
) -> SpeedOutcome:
    """Download through the profile's tunnel and rate the achieved quality."""
    try:
        return await asyncio.wait_for(
            _measure_through_tunnel(profile, settings, latency_component),
            timeout=settings.max_duration_seconds + settings.timeout_seconds,
        )
    except TimeoutError:
        return SpeedOutcome(False, reason="tunnel_timeout")
    except socket.gaierror:
        return SpeedOutcome(False, reason="dns_error")
    except ConnectionRefusedError:
        return SpeedOutcome(False, reason="connection_refused")
    except ssl.SSLError:
        return SpeedOutcome(False, reason="tls_error")
    except _HandshakeError:
        return SpeedOutcome(False, reason="handshake_rejected")
    except _UpstreamError:
        return SpeedOutcome(False, reason="upstream_status")
    except (OSError, ValueError):
        return SpeedOutcome(False, reason="tunnel_error")


async def _measure_through_tunnel(
    profile: Profile,
    settings: SpeedTestConfig,
    latency_component: float | None,
) -> SpeedOutcome:
    parts = urlsplit(settings.download_url)
    relay, _, _ = await _open_relay(profile, settings)
    try:
        await relay.send(_http_request(parts))
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = await relay.receive()
            if not chunk:
                raise _UpstreamError("empty response from bulk endpoint")
            header += chunk
        head, _, body = header.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            raise _UpstreamError(f"unexpected status from bulk endpoint: {status!r}")
        relay.push_back(body)

        received_total = 0
        # Warm-up: absorb TCP slow-start so it cannot depress the first window.
        warmup_seconds = min(max(settings.warmup_seconds, 0.0), settings.max_duration_seconds)
        warmup_started_at = perf_counter()
        warmup_bytes = 0
        while warmup_seconds > 0 and received_total < settings.download_bytes:
            budget = warmup_seconds - (perf_counter() - warmup_started_at)
            if budget <= 0:
                break
            try:
                chunk = await asyncio.wait_for(relay.receive(), timeout=budget)
            except TimeoutError:
                break
            if not chunk:
                break
            received_total += len(chunk)
            warmup_bytes += len(chunk)
        warmup_elapsed = perf_counter() - warmup_started_at

        # Measurement: split the remaining budget into equal analysis windows.
        windows = max(settings.windows, 1)
        window_duration = settings.max_duration_seconds / windows
        window_speeds: list[float] = []
        measured_seconds = 0.0
        measured_bytes = 0
        drained = False
        for _ in range(windows):
            window_started_at = perf_counter()
            window_bytes = 0
            while received_total < settings.download_bytes:
                budget = window_duration - (perf_counter() - window_started_at)
                if budget <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(relay.receive(), timeout=budget)
                except TimeoutError:
                    break
                if not chunk:
                    drained = True
                    break
                window_bytes += len(chunk)
                received_total += len(chunk)
            elapsed = perf_counter() - window_started_at
            measured_seconds += elapsed
            measured_bytes += window_bytes
            window_speeds.append(window_bytes / 1024 / max(elapsed, 1e-6))
            if drained or received_total >= settings.download_bytes:
                break

        if measured_bytes == 0 and warmup_bytes > 0:
            # The transfer finished inside the warm-up window (small payload on a
            # fast tunnel): those bytes are real delivered throughput, so they
            # become the single measurement sample instead of a zero reading.
            window_speeds = [warmup_bytes / 1024 / max(warmup_elapsed, 1e-6)]
            measured_bytes = warmup_bytes
            measured_seconds = warmup_elapsed
        mean_kbps = measured_bytes / 1024 / max(measured_seconds, 1e-6)
        peak_kbps = max(window_speeds, default=0.0)
        if len(window_speeds) >= 2:
            jitter = statistics.pstdev(window_speeds)
            stability = min(min(window_speeds) / mean_kbps, 1.0) if mean_kbps > 0 else 0.0
        else:
            jitter = None
            stability = 1.0
        score, grade = quality_score(
            mean_kbps,
            stability,
            latency_component,
            target_kbps=settings.target_kbps,
        )
        rounded_mean = round(mean_kbps, 1)
        windows_payload = tuple(round(value, 1) for value in window_speeds)
        rounded_jitter = round(jitter, 1) if jitter is not None else None

        def outcome(passed: bool, reason: str | None) -> SpeedOutcome:
            return SpeedOutcome(
                passed,
                rounded_mean,
                reason,
                round(peak_kbps, 1),
                windows_payload,
                rounded_jitter,
                round(stability, 3),
                score,
                grade,
            )

        if mean_kbps < settings.min_kbps:
            return outcome(False, "slow_endpoint")
        if received_total < _EVIDENCE_BYTES:
            return outcome(False, "insufficient_data")
        if settings.min_stability > 0.0 and stability < settings.min_stability:
            return outcome(False, "unstable_endpoint")
        return outcome(True, None)
    finally:
        await relay.aclose()


async def run_speed_tests(
    profiles: Sequence[Profile],
    settings: SpeedTestConfig,
    latency_components: Mapping[int, float] | None = None,
) -> dict[int, SpeedOutcome]:
    """Measure every profile concurrently in batches keyed by object identity.

    ``latency_components`` optionally maps ``id(profile)`` to a 0-100 latency
    component produced by the reachability stage; missing entries score neutral.
    """
    outcomes: dict[int, SpeedOutcome] = {}
    shared_components = latency_components or {}
    semaphore = asyncio.Semaphore(settings.workers)

    async def measure_one(profile: Profile) -> None:
        if not tunnel_supported(profile):
            outcomes[id(profile)] = SpeedOutcome(False, reason="speed_unsupported")
            return
        async with semaphore:
            outcome = await measure_profile(
                profile, settings, shared_components.get(id(profile))
            )
            outcomes[id(profile)] = outcome

    for start in range(0, len(profiles), settings.batch_size):
        batch: Iterable[Profile] = profiles[start : start + settings.batch_size]
        await asyncio.gather(*(measure_one(profile) for profile in batch))
    return outcomes
