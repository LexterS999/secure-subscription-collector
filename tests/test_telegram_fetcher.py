import asyncio
from datetime import UTC, datetime

import httpx

from subscription_collector.fetcher import fetch_telegram_previews
from subscription_collector.models import Freshness

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def test_preview_fetch_uses_canonical_https_url(config_for) -> None:
    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(200, text="<html></html>")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_telegram_previews(
                ["Channel_Name"], client, NOW, config_for().telegram
            )

        assert results[0].freshness is Freshness.UNKNOWN
        assert results[0].text == "<html></html>"
        assert requests == ["https://t.me/s/channel_name"]

    asyncio.run(exercise())


def test_preview_fetch_rejects_redirect_to_non_https(config_for) -> None:
    async def exercise() -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://not-allowed.example"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_telegram_previews(
                ["channel_name"], client, NOW, config_for().telegram
            )

        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == "redirect_non_https"

    asyncio.run(exercise())


def test_preview_fetch_caps_response_size(config_for) -> None:
    async def exercise() -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"x" * 64)

        settings = config_for().telegram
        settings = type(settings)(
            registry_path=settings.registry_path,
            state_path=settings.state_path,
            max_post_age_hours=settings.max_post_age_hours,
            concurrency=settings.concurrency,
            timeout_seconds=settings.timeout_seconds,
            max_response_bytes=16,
            max_redirects=settings.max_redirects,
            max_pages_per_channel=settings.max_pages_per_channel,
            sample_post_limit=settings.sample_post_limit,
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_telegram_previews(["channel_name"], client, NOW, settings)

        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == "response_too_large"

    asyncio.run(exercise())
