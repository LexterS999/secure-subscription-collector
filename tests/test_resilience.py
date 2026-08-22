"""Regression tests for bounded network work: deadlines, retries, and progress.

These tests pin the anti-hang contract of the collection pipeline:
every document download finishes under a total deadline even when a server
trickles bytes forever, transient failures retry with backoff, deterministic
security failures never retry, channel pagination is finite, and long stages
report progress instead of going silent.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml

from subscription_collector.config_loader import ConfigError, load_config
from subscription_collector.fetcher import fetch_channel_posts, fetch_sources
from subscription_collector.models import Freshness

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)


def _write_config(tmp_path: Path, payload: dict) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return config_path


@pytest.fixture
def base_payload() -> dict:
    return {
        "paths": {
            "input": "input.txt",
            "output_dir": "output",
            "report": "report.json",
            "state": ".collector/state.json",
        },
        "sources": {
            "max_age_hours": 72,
            "concurrency": 48,
            "timeout_seconds": 20.0,
            "max_response_bytes": 5242880,
            "max_redirects": 3,
            "user_agent": "secure-subscription-collector/0.1",
        },
        "static_filter": {"workers": 160, "batch_size": 1024},
        "behavior": {"strict_first_seen": False, "fail_on_empty": False},
    }


def test_slow_drip_source_finishes_at_total_deadline(config_for) -> None:
    """A server trickling bytes forever must fail at the deadline, not hang."""

    async def exercise() -> tuple[str | None, float]:
        async def drip() -> httpx.AsyncByteStream:  # pragma: no cover - transport glue
            for _ in range(1000):
                yield b"x"
                await asyncio.sleep(0.05)

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=drip())

        settings = replace(config_for().sources, total_deadline_seconds=1.0)
        started_at = time.perf_counter()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, NOW, settings
            )
        return results[0].reason, time.perf_counter() - started_at

    reason, elapsed = asyncio.run(exercise())
    assert reason == "deadline_exceeded"
    assert elapsed < 5.0


def test_transient_network_failure_is_retried_and_recovers(config_for) -> None:
    """A source failing twice with connection errors still loads after retries."""
    attempts = 0

    async def exercise() -> tuple[object, str | None, int]:
        nonlocal attempts

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise httpx.ConnectError("connection refused", request=httpx.Request(
                    "GET", "https://source.example/list"
                ))
            return httpx.Response(200, text=TROJAN_TLS)

        settings = replace(config_for().sources, retries=2, retry_backoff_seconds=0.01)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, NOW, settings
            )
        return results[0].freshness, results[0].text, attempts

    freshness, text, total_attempts = asyncio.run(exercise())
    assert total_attempts == 3
    assert freshness in {Freshness.RECENT, Freshness.UNKNOWN}
    assert text == TROJAN_TLS


def test_rate_limit_with_retry_after_is_retried(config_for) -> None:
    """A 429 answer with Retry-After is honored and the source is recovered."""
    attempts = 0

    async def exercise() -> tuple[str | None, int]:
        nonlocal attempts

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, text=TROJAN_TLS)

        settings = replace(config_for().sources, retries=2, retry_backoff_seconds=0.01)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, NOW, settings
            )
        return results[0].reason, attempts

    reason, total_attempts = asyncio.run(exercise())
    assert total_attempts == 2
    assert reason is None


def test_deterministic_redirect_failure_never_retries(config_for) -> None:
    """Security-relevant redirect failures are final after the first attempt."""
    requests: list[str] = []

    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(302, headers={"Location": "http://downgrade.example/list"})

        settings = replace(config_for().sources, retries=3, retry_backoff_seconds=0.01)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await fetch_sources(["https://source.example/list"], client, NOW, settings)

    asyncio.run(exercise())
    assert requests == ["https://source.example/list"]


def test_channel_pagination_stops_at_max_pages(config_for) -> None:
    """One channel cannot page forever: the page cap bounds its requests."""
    requests: list[str] = []
    fresh = "2026-08-15T11:30:00+00:00"
    counter = {"next_id": 1000}

    async def exercise() -> None:
        def page(message_id: int) -> str:
            return f"""
            <div class="tgme_widget_message" data-post="channel_name/{message_id}">
              <div class="tgme_widget_message_text">vless://profile-{message_id}</div>
              <time datetime="{fresh}"></time>
            </div>
            """

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            counter["next_id"] -= 1
            return httpx.Response(200, text=page(counter["next_id"]))

        settings = replace(config_for().telegram, max_pages_per_channel=5)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            previews = await fetch_channel_posts(["channel_name"], client, NOW, settings)

        assert len(previews["channel_name"].posts) == 5

    asyncio.run(exercise())
    assert len(requests) == 5


def test_fetch_sources_reports_monotonic_progress(config_for) -> None:
    """The fetch stage reports (completed, total) progress for live telemetry."""
    updates: list[tuple[int, int]] = []

    async def exercise() -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=TROJAN_TLS)

        urls = [f"https://source.example/{index}" for index in range(7)]
        settings = replace(config_for().sources, retries=0)

        def record(done: int, total: int) -> None:
            updates.append((done, total))

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await fetch_sources(urls, client, NOW, settings, progress=record)

    asyncio.run(exercise())
    assert updates[-1] == (7, 7)
    completed = [done for done, _ in updates]
    assert completed == sorted(completed)
    assert len(set(completed)) == len(completed)


def test_sources_defaults_apply_to_legacy_configs(base_payload: dict, tmp_path: Path) -> None:
    """Configs written before the retry/deadline settings keep loading."""
    config = load_config(_write_config(tmp_path, base_payload))

    assert config.sources.connect_timeout_seconds == 10.0
    assert config.sources.total_deadline_seconds == 30.0
    assert config.sources.retries == 2
    assert config.sources.retry_backoff_seconds == 1.0
    assert config.telegram.connect_timeout_seconds == 10.0
    assert config.telegram.total_deadline_seconds == 25.0
    assert config.telegram.retries == 2


def test_sources_retry_settings_are_validated(base_payload: dict, tmp_path: Path) -> None:
    """Nonsensical retry or deadline values are rejected with a config error."""
    base_payload["sources"]["retries"] = 9
    with pytest.raises(ConfigError):
        load_config(_write_config(tmp_path, base_payload))

    base_payload["sources"]["retries"] = 2
    base_payload["sources"]["total_deadline_seconds"] = 5.0
    with pytest.raises(ConfigError):
        load_config(_write_config(tmp_path, base_payload))


def test_stale_source_stays_excluded_after_retries(config_for) -> None:
    """Retries never resurrect stale content: the freshness gate is untouched."""
    old = NOW - timedelta(hours=72, seconds=1)

    async def exercise() -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Last-Modified": old.strftime("%a, %d %b %Y %H:%M:%S GMT")},
                text=TROJAN_TLS,
            )

        settings = replace(config_for().sources, retries=2, retry_backoff_seconds=0.01)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, NOW, settings
            )
        assert results[0].freshness is Freshness.STALE
        assert results[0].text is None

    asyncio.run(exercise())
