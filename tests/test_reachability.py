from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import yaml

from subscription_collector.config_loader import (
    ConfigError,
    ReachabilityConfig,
    load_config,
)
from subscription_collector.parser import parse_profile
from subscription_collector.reachability import (
    Endpoint,
    endpoint_of,
    probe_endpoint,
    probe_endpoints,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

VLESS_TLS = (
    "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
    "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=tcp"
)
HYSTERIA2 = "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com"


@asynccontextmanager
async def greeting_server() -> AsyncIterator[int]:
    """Local TCP server that reads the request and answers like a web origin."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def silent_server() -> AsyncIterator[int]:
    """Local TCP server that completes the handshake but never answers."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(5)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def test_responsive_endpoint_confirms_via_cloudflare_trace_path() -> None:
    """A live TCP endpoint that answers HTTP is confirmed by the trace request."""

    async def exercise() -> tuple[bool, str]:
        async with greeting_server() as port:
            probe = await probe_endpoint(Endpoint("127.0.0.1", port, False, ""), 1.0)
        return probe.responded, probe.method

    responded, method = asyncio.run(exercise())
    assert responded is True
    assert method == "cloudflare_trace"


def test_closed_port_is_reported_unresponsive() -> None:
    """A refused TCP handshake marks the endpoint as dead without retries."""

    async def exercise() -> tuple[bool, int]:
        server = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        probe = await probe_endpoint(Endpoint("127.0.0.1", port, False, ""), 1.0)
        return probe.responded, probe.port

    responded, port = asyncio.run(exercise())
    assert responded is False
    assert port > 0


def test_silent_endpoint_consumes_the_deadline_without_confirmation() -> None:
    """A host that accepts TCP but never answers HTTP keeps only the TCP verdict."""

    async def exercise() -> tuple[bool, str]:
        async with silent_server() as port:
            probe = await probe_endpoint(Endpoint("127.0.0.1", port, False, ""), 0.3)
        return probe.responded, probe.method

    responded, method = asyncio.run(exercise())
    assert responded is True
    assert method == "tcp"


def test_hysteria2_is_exempt_from_the_tcp_probe() -> None:
    """QUIC-based profiles never face the TCP probe and stay publishable."""
    profile = parse_profile(HYSTERIA2, "https://source.example/list")
    assert profile is not None
    assert endpoint_of(profile) is None


def test_tls_endpoint_carries_profile_sni() -> None:
    profile = parse_profile(VLESS_TLS, "https://source.example/list")
    assert profile is not None
    assert endpoint_of(profile) == Endpoint("node.example.org", 443, True, "www.example.com")


def test_probe_endpoints_reports_each_unique_endpoint_once() -> None:
    """Duplicate endpoints collapse into a single probe result per address."""

    async def exercise() -> dict[Endpoint, bool]:
        async with greeting_server() as port:
            settings = ReachabilityConfig(workers=50, batch_size=8, timeout_ms=1000)
            duplicated = Endpoint("127.0.0.1", port, False, "")
            closed = Endpoint("127.0.0.1", 1, False, "")
            outcomes = await probe_endpoints([duplicated, duplicated, closed], settings)
        return {key: value.responded for key, value in outcomes.items()}

    outcomes = asyncio.run(exercise())
    assert len(outcomes) == 2
    assert any(responded for responded in outcomes.values())
    assert not all(responded for responded in outcomes.values())


def test_unresolvable_domain_falls_back_to_google_doh() -> None:
    """A domain the system resolver cannot answer is retried via Google DNS JSON API."""

    async def exercise() -> tuple[bool, list[str]]:
        async with greeting_server() as port:
            calls: list[str] = []

            def handler(request: httpx.Request) -> httpx.Response:
                calls.append(str(request.url))
                return httpx.Response(200, json={"Answer": [{"type": 1, "data": "127.0.0.1"}]})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler), timeout=2.0
            ) as client:
                probe = await probe_endpoint(
                    Endpoint("unresolvable-domain.invalid", port, False, ""),
                    1.0,
                    dns_fallback_client=client,
                )
        return probe.responded, calls

    responded, calls = asyncio.run(exercise())
    assert responded is True
    assert calls and calls[0].startswith("https://dns.google/resolve")


def test_domain_without_doh_answer_is_discarded() -> None:
    """When neither the system resolver nor Google DNS answers, the endpoint dies."""

    async def exercise() -> bool:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"Answer": []})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=2.0) as client:
            probe = await probe_endpoint(
                Endpoint("unresolvable-domain.invalid", 443, False, ""),
                1.0,
                dns_fallback_client=client,
            )
        return probe.responded

    assert asyncio.run(exercise()) is False


def test_default_reachability_settings_match_documented_values() -> None:
    config = load_config(PROJECT_ROOT / "config.yaml")
    assert config.reachability == ReachabilityConfig(workers=56, batch_size=256, timeout_ms=1000)


@pytest.mark.parametrize("workers", [49, 61])
def test_worker_count_is_bounded_to_documented_range(tmp_path: Path, workers: int) -> None:
    config_path = tmp_path / "config.yaml"
    payload = yaml.safe_load((PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8"))
    payload["reachability"]["workers"] = workers
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match="от 50 до 60"):
        load_config(config_path)


def test_timeout_above_one_second_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    payload = yaml.safe_load((PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8"))
    payload["reachability"]["timeout_ms"] = 1500
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match="от 1 до 1000"):
        load_config(config_path)
