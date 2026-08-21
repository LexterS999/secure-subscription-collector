import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import httpx

from subscription_collector.fetcher import fetch_recent_telegram_posts, fetch_telegram_previews
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

        settings = replace(config_for().telegram, max_response_bytes=16)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_telegram_previews(["channel_name"], client, NOW, settings)

        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == "response_too_large"

    asyncio.run(exercise())


def test_recent_post_fetcher_paginates_until_preview_reaches_old_messages(config_for) -> None:
    async def exercise() -> None:
        requests: list[str] = []
        fresh = "2026-08-15T11:30:00+00:00"
        old = "2026-08-11T11:30:00+00:00"

        def page(message_id: int, published_at: str) -> str:
            return f"""
            <div class="tgme_widget_message" data-post="channel_name/{message_id}">
              <div class="tgme_widget_message_text">vless://profile-{message_id}</div>
              <time datetime="{published_at}"></time>
            </div>
            """

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(
                200,
                text=page(20, fresh) if request.url.params.get("before") is None else page(19, old),
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            posts = await fetch_recent_telegram_posts(
                ["Channel_Name"], client, NOW, config_for().telegram
            )

        assert [post.message_id for post in posts] == ["20"]
        assert requests == ["https://t.me/s/channel_name", "https://t.me/s/channel_name?before=20"]

    asyncio.run(exercise())
