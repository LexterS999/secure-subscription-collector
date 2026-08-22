"""Stage-boundary integration tests: the reported incident cannot repeat.

Simulates a full «Загрузка источников» wave of 74 sources mixing healthy feeds,
slow-drip servers, flaky connections, and hard-failing endpoints, and asserts the
stage finishes in bounded time with correct outcomes. Pins the pagination cap
under channel pressure as well.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime

import httpx

from subscription_collector.fetcher import fetch_channel_posts, fetch_sources
from subscription_collector.models import Freshness

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)

TOTAL_SOURCES = 74


class _SlowDripStream(httpx.AsyncByteStream):
    """Endless response that trickles one byte at a time, defeating read timeouts."""

    async def __aiter__(self):
        while True:  # pragma: no cover - bounded by the total deadline, not this loop
            yield b"x"
            await asyncio.sleep(0.02)


def _build_handler(state: dict[str, int]):
    """Route each source index through its scripted failure mode."""

    def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.path.rsplit("/", 1)[-1])
        state.setdefault(f"attempts:{index}", 0)
        state[f"attempts:{index}"] += 1
        if index < 20:  # slow-drip servers: hang until the total deadline
            return httpx.Response(200, content=_SlowDripStream())
        if index < 27:  # flaky hosts: two transient refusals, then healthy
            if state[f"attempts:{index}"] < 3:
                raise httpx.ConnectError("connection refused", request=request)
            return httpx.Response(200, text=TROJAN_TLS)
        if index < 31:  # permanently broken gateways
            return httpx.Response(503)
        return httpx.Response(200, text=TROJAN_TLS)  # the healthy majority

    return handler


def test_sources_wave_with_pathological_hosts_finishes_bounded(config_for) -> None:
    """74 sources incl. 20 infinite-drip hosts complete inside the stage budget."""
    state: dict[str, int] = {}
    progress: list[tuple[int, int]] = []

    async def exercise() -> tuple[float, list[object]]:
        urls = [f"https://source.example/{index}" for index in range(TOTAL_SOURCES)]
        settings = replace(
            config_for().sources,
            timeout_seconds=1.0,
            connect_timeout_seconds=0.5,
            total_deadline_seconds=2.0,
            retries=2,
            retry_backoff_seconds=0.01,
        )

        def record(done: int, total: int) -> None:
            progress.append((done, total))

        started_at = time.perf_counter()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_build_handler(state))
        ) as client:
            results = await fetch_sources(urls, client, NOW, settings, progress=record)
        return time.perf_counter() - started_at, results

    elapsed, results = asyncio.run(exercise())
    assert len(results) == TOTAL_SOURCES

    # The stage finished instead of hanging: every drip source hit its deadline.
    drip_reasons = {results[index].reason for index in range(20)}
    assert drip_reasons == {"deadline_exceeded"}
    # Flaky hosts recovered through retries; broken gateways are classified.
    flaky_ok = all(results[index].text == TROJAN_TLS for index in range(20, 27))
    gateway_failed = all(results[index].reason == "http_503" for index in range(27, 31))
    healthy = {Freshness.RECENT, Freshness.UNKNOWN}
    healthy_ok = all(results[index].freshness in healthy for index in range(31, 74))
    assert flaky_ok and gateway_failed and healthy_ok
    # Progress telemetry fired during the wave, ending with the full count.
    assert progress[-1] == (TOTAL_SOURCES, TOTAL_SOURCES)
    assert len(progress) >= 2
    # Bounded wall clock: two deadline waves plus retries stay far under minutes.
    assert elapsed < 15.0


def test_many_channels_under_pressure_stay_bounded(config_for) -> None:
    """Ten endlessly-paginating channels finish at the configured page cap."""
    request_count = {"pages": 0}
    fresh = "2026-08-15T11:30:00+00:00"

    async def exercise() -> None:
        def page(handle: str, message_id: int) -> str:
            return f"""
            <div class="tgme_widget_message" data-post="{handle}/{message_id}">
              <div class="tgme_widget_message_text">vless://profile-{message_id}</div>
              <time datetime="{fresh}"></time>
            </div>
            """

        def handler(request: httpx.Request) -> httpx.Response:
            handle = request.url.path.rstrip("/").rsplit("/", 1)[-1]
            before = request.url.params.get("before")
            next_id = int(before) - 1 if before else 10_000
            request_count["pages"] += 1
            return httpx.Response(200, text=page(handle, next_id))

        handles = [f"channel_{index}" for index in range(10)]
        settings = replace(config_for().telegram, max_pages_per_channel=3)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            previews = await fetch_channel_posts(handles, client, NOW, settings)

        assert len(previews) == 10
        assert all(len(preview.posts) == 3 for preview in previews.values())

    asyncio.run(exercise())
    assert request_count["pages"] == 30
