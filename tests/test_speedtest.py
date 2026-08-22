from __future__ import annotations

import asyncio
import hashlib
import struct
from dataclasses import replace

import httpx
import pytest

from subscription_collector import cli
from subscription_collector.config_loader import load_config
from subscription_collector.models import Profile
from subscription_collector.parser import parse_profile
from subscription_collector.speedtest import (
    SpeedOutcome,
    measure_profile,
    run_speed_tests,
    tunnel_supported,
)

INNER_HOST = "bulk.example"
HTTP_REQUEST = (
    f"GET /f.bin HTTP/1.1\r\nHost: {INNER_HOST}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
)
TROJAN_URI = "trojan://strong-password@127.0.0.1:{port}?security=none&type=tcp#speed-check"
VLESS_WS_URI = (
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@127.0.0.1:{port}"
    "?type=ws&path=%2Fws&security=none#speed-check"
)
SOURCE_URI = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#gating"
)


def _settings(**overrides: object):
    base = replace(
        load_config("config.yaml").speed_test,
        download_url=f"http://{INNER_HOST}/f.bin",
        timeout_seconds=3.0,
        max_duration_seconds=2.0,
    )
    return replace(base, **overrides)


def _profile(uri: str) -> Profile:
    parsed = parse_profile(uri, "https://source.example/list")
    assert parsed is not None
    return parsed


def _address() -> bytes:
    encoded = INNER_HOST.encode()
    return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack(">H", 80)


async def _read_until_http_end(reader: asyncio.StreamReader) -> bytes:
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = await reader.read(4096)
        if not chunk:
            break
        buffer += chunk
    return buffer


def _http_response(body: bytes) -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def test_tunnel_supported_covers_only_core_free_combinations() -> None:
    assert tunnel_supported(_profile(TROJAN_URI.format(port=443)))
    assert tunnel_supported(_profile(VLESS_WS_URI.format(port=80)))
    hysteria = _profile("hysteria2://pw@127.0.0.1:443/#check")
    reality = _profile(
        "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@127.0.0.1:443?security=reality&type=tcp#check"
    )
    assert not tunnel_supported(hysteria)
    assert not tunnel_supported(reality)


def test_trojan_handshake_and_fast_stream_passes() -> None:
    seen: list[bytes] = []

    async def exercise() -> SpeedOutcome:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            seen.append(await _read_until_http_end(reader))
            writer.write(_http_response(b"z" * 400_000))
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await measure_profile(_profile(TROJAN_URI.format(port=port)), _settings())
        finally:
            server.close()
            await server.wait_closed()

    outcome = asyncio.run(exercise())
    assert outcome.passed is True
    digest = hashlib.sha224(b"strong-password").hexdigest().encode()
    assert seen[0] == digest + b"\r\n\x01" + _address() + b"\r\n" + HTTP_REQUEST.encode()


def test_vless_websocket_handshake_and_stream_passes() -> None:
    seen: list[list[bytes]] = []

    async def read_client_frame(reader: asyncio.StreamReader) -> bytes:
        first, second = await reader.readexactly(2)
        assert first == 0x82
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", await reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await reader.readexactly(8))[0]
        mask = await reader.readexactly(4)
        framed = await reader.readexactly(length)
        return bytes(byte ^ mask[index % 4] for index, byte in enumerate(framed))

    async def exercise() -> SpeedOutcome:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            head: list[bytes] = []
            while True:
                line = await reader.readline()
                if line in {b"\r\n", b""}:
                    break
                head.append(line)
            seen.append(head)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
            await writer.drain()
            user_id = bytes.fromhex("d342d11ed4244583b36e524ab1f0afa4")
            header_frame = await read_client_frame(reader)
            assert header_frame == b"\x00" + user_id + b"\x00\x01" + _address()
            writer.write(b"\x82\x02\x00\x00")
            await writer.drain()
            request = b""
            while b"\r\n\r\n" not in request:
                request += await read_client_frame(reader)
            assert request.startswith(b"GET /f.bin")
            body = _http_response(b"w" * 400_000)
            writer.write(b"\x82\x7f" + struct.pack(">Q", len(body)) + body)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await measure_profile(_profile(VLESS_WS_URI.format(port=port)), _settings())
        finally:
            server.close()
            await server.wait_closed()

    outcome = asyncio.run(exercise())
    assert outcome.passed is True
    assert any(line.startswith(b"GET /ws ") for line in seen[0])


def test_slow_trickle_is_rejected_as_slow_endpoint() -> None:
    async def exercise() -> SpeedOutcome:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _read_until_http_end(reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
            await writer.drain()
            for _ in range(8):
                writer.write(b"x" * 2048)
                await writer.drain()
                await asyncio.sleep(0.05)
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await measure_profile(
                _profile(TROJAN_URI.format(port=port)),
                _settings(max_duration_seconds=0.2),
            )
        finally:
            server.close()
            await server.wait_closed()

    outcome = asyncio.run(exercise())
    assert outcome.passed is False
    assert outcome.reason == "slow_endpoint"


def test_fast_but_short_response_is_insufficient_data() -> None:
    async def exercise() -> SpeedOutcome:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _read_until_http_end(reader)
            writer.write(_http_response(b"x" * 4096))
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await measure_profile(_profile(TROJAN_URI.format(port=port)), _settings())
        finally:
            server.close()
            await server.wait_closed()

    outcome = asyncio.run(exercise())
    assert outcome.reason == "insufficient_data"


def test_refusing_connection_maps_to_tunnel_error() -> None:
    outcome = asyncio.run(measure_profile(_profile(TROJAN_URI.format(port=1)), _settings()))
    assert outcome.passed is False
    assert outcome.reason == "tunnel_error"


def test_run_speed_tests_marks_unsupported_profiles() -> None:
    profiles = [
        _profile("hysteria2://pw@127.0.0.1:443/#check"),
        _profile(TROJAN_URI.format(port=1)),
    ]

    async def exercise() -> dict[int, SpeedOutcome]:
        return await run_speed_tests(profiles, _settings())

    outcomes = asyncio.run(exercise())
    assert outcomes[id(profiles[0])].reason == "speed_unsupported"
    assert outcomes[id(profiles[1])].reason == "tunnel_error"


@pytest.mark.parametrize("mode,expected_kept", [("strict", 0), ("best_effort", 1)])
def test_pipeline_gating_respects_mode(
    tmp_path, monkeypatch, config_for, mode: str, expected_kept: int
) -> None:
    async def fake_speed_tests(profiles, settings):
        return {
            id(profile): SpeedOutcome(False, reason="speed_unsupported") for profile in profiles
        }

    monkeypatch.setattr(cli, "run_speed_tests", fake_speed_tests)

    async def exercise() -> int:
        input_path = tmp_path / "input.txt"
        output_dir = tmp_path / "output"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=SOURCE_URI + "\n")

        config = replace(config_for(input_path=input_path, output_dir=output_dir))
        config = replace(config, speed_test=replace(config.speed_test, mode=mode))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await cli.run_collection(config=config, client=client)

    assert asyncio.run(exercise()) == 0
    published = tmp_path / "output" / "trojan.txt"
    kept = len(published.read_text(encoding="utf-8").splitlines()) if published.exists() else 0
    assert kept == expected_kept
