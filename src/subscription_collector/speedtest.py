"""Tunnel throughput measurement for proxy profiles.

The probe speaks the minimal client side of VLESS and Trojan, relays to a public
bulk-download endpoint through the profile's own tunnel, and reports how many
kilobytes per second the endpoint actually delivered. Protocol combinations that
require a dedicated client core (Hysteria2 over QUIC, VLESS over Reality or
gRPC) are reported as ``speed_unsupported`` so callers can apply their own
policy instead of guessing.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import os
import ssl
import struct
import uuid
from collections.abc import Iterable, Sequence
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


@dataclass(frozen=True, slots=True)
class SpeedOutcome:
    """Result of one throughput measurement."""

    passed: bool
    kbps: float | None = None
    reason: str | None = None


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
            raise ConnectionError("websocket upgrade failed")
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
                    raise ConnectionError("vless handshake rejected")
                header += chunk
            if header[0] != 0x00:
                raise ConnectionError("vless handshake rejected")
            needed = 2 + header[1]
            while len(header) < needed:
                chunk = await relay.receive()
                if not chunk:
                    raise ConnectionError("vless handshake truncated")
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


async def measure_profile(profile: Profile, settings: SpeedTestConfig) -> SpeedOutcome:
    """Download through the profile's tunnel and rate the achieved speed."""
    try:
        return await asyncio.wait_for(
            _measure_through_tunnel(profile, settings),
            timeout=settings.max_duration_seconds + settings.timeout_seconds,
        )
    except TimeoutError:
        return SpeedOutcome(False, reason="tunnel_timeout")
    except (OSError, ValueError):
        return SpeedOutcome(False, reason="tunnel_error")


async def _measure_through_tunnel(profile: Profile, settings: SpeedTestConfig) -> SpeedOutcome:
    parts = urlsplit(settings.download_url)
    relay, _, _ = await _open_relay(profile, settings)
    try:
        await relay.send(_http_request(parts))
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = await relay.receive()
            if not chunk:
                raise ConnectionError("empty response from bulk endpoint")
            header += chunk
        head, _, body = header.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            raise ConnectionError(f"unexpected status from bulk endpoint: {status!r}")
        relay.push_back(body)
        received = 0
        started_at = perf_counter()
        while received < settings.download_bytes:
            budget = settings.max_duration_seconds - (perf_counter() - started_at)
            if budget <= 0:
                break
            try:
                chunk = await asyncio.wait_for(relay.receive(), timeout=budget)
            except TimeoutError:
                break
            if not chunk:
                break
            received += len(chunk)
        elapsed = max(perf_counter() - started_at, 1e-6)
        kbps = received / 1024 / elapsed
        if received >= _EVIDENCE_BYTES and kbps >= settings.min_kbps:
            return SpeedOutcome(True, kbps=round(kbps, 1))
        if kbps >= settings.min_kbps:
            return SpeedOutcome(False, kbps=round(kbps, 1), reason="insufficient_data")
        return SpeedOutcome(False, kbps=round(kbps, 1), reason="slow_endpoint")
    finally:
        await relay.aclose()


async def run_speed_tests(
    profiles: Sequence[Profile], settings: SpeedTestConfig
) -> dict[int, SpeedOutcome]:
    """Measure every profile concurrently in batches keyed by object identity."""
    outcomes: dict[int, SpeedOutcome] = {}
    semaphore = asyncio.Semaphore(settings.workers)

    async def measure_one(profile: Profile) -> None:
        if not tunnel_supported(profile):
            outcomes[id(profile)] = SpeedOutcome(False, reason="speed_unsupported")
            return
        async with semaphore:
            outcomes[id(profile)] = await measure_profile(profile, settings)

    for start in range(0, len(profiles), settings.batch_size):
        batch: Iterable[Profile] = profiles[start : start + settings.batch_size]
        await asyncio.gather(*(measure_one(profile) for profile in batch))
    return outcomes
