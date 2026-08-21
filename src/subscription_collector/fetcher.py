from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx

from .config_loader import SourcesConfig, TelegramConfig
from .models import Freshness, SourceResult, TelegramPost
from .telegram import canonical_preview_url, parse_preview_posts


def _parse_last_modified(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None:
        return None
    return parsed.astimezone(UTC)


async def _read_document(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_response_bytes: int,
    max_redirects: int,
    timeout_seconds: float,
) -> tuple[str | None, str | None, str | None]:
    """Fetch one HTTPS document without following unsafe redirects.

    Returns ``(text, failure_reason, last_modified_header)``; ``text`` is set only when
    the reason is ``None``.
    """
    request_url = url
    try:
        for redirect_count in range(max_redirects + 1):
            response = await client.get(
                request_url, follow_redirects=False, timeout=timeout_seconds
            )
            if response.is_redirect:
                location = response.headers.get("Location")
                if redirect_count == max_redirects:
                    return None, "too_many_redirects", None
                if not location:
                    return None, "redirect_without_location", None
                try:
                    location_parts = urlsplit(location)
                    if location_parts.scheme and not location_parts.netloc:
                        raise ValueError("redirect URL has no host")
                    next_url = str(response.url.join(location))
                    next_parts = urlsplit(next_url)
                except ValueError:
                    return None, "redirect_invalid_location", None
                if next_parts.scheme != "https" or not next_parts.netloc:
                    return None, "redirect_non_https", None
                if next_parts.username or next_parts.password:
                    return None, "redirect_credentials", None
                request_url = next_url
                continue
            response.raise_for_status()
            content = response.content
            if len(content) > max_response_bytes:
                return None, "response_too_large", None
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return None, "invalid_utf8", None
            return text, None, response.headers.get("Last-Modified")
        return None, "too_many_redirects", None
    except httpx.TimeoutException:
        return None, "timeout", None
    except httpx.HTTPError as error:
        return None, f"http_error:{type(error).__name__}", None


async def _fetch_one(
    url: str,
    client: httpx.AsyncClient,
    now: datetime,
    settings: SourcesConfig,
    semaphore: asyncio.Semaphore,
) -> SourceResult:
    async with semaphore:
        text, reason, raw_header = await _read_document(
            client,
            url,
            max_response_bytes=settings.max_response_bytes,
            max_redirects=settings.max_redirects,
            timeout_seconds=settings.timeout_seconds,
        )
    if reason is not None or text is None:
        return SourceResult(url, Freshness.FAILED, None, reason=reason or "fetch_failed")

    modified = _parse_last_modified(raw_header)
    if modified is None:
        return SourceResult(url, Freshness.UNKNOWN, text, last_modified=None)
    age_seconds = (now.astimezone(UTC) - modified).total_seconds()
    if age_seconds > settings.max_age_hours * 3600:
        return SourceResult(url, Freshness.STALE, None, last_modified=modified.isoformat())
    return SourceResult(url, Freshness.RECENT, text, last_modified=modified.isoformat())


async def fetch_sources(
    urls: list[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: SourcesConfig,
) -> list[SourceResult]:
    """Fetch subscription documents without contacting addresses contained in them."""
    semaphore = asyncio.Semaphore(settings.concurrency)
    return list(
        await asyncio.gather(*(_fetch_one(url, client, now, settings, semaphore) for url in urls))
    )


async def fetch_telegram_previews(
    handles: Sequence[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: TelegramConfig,
) -> list[SourceResult]:
    """Fetch canonical public preview pages for normalized handles only."""
    semaphore = asyncio.Semaphore(settings.concurrency)

    async def fetch_preview(handle: str) -> SourceResult:
        url = canonical_preview_url(handle)
        async with semaphore:
            text, reason, _ = await _read_document(
                client,
                url,
                max_response_bytes=settings.max_response_bytes,
                max_redirects=settings.max_redirects,
                timeout_seconds=settings.timeout_seconds,
            )
        if reason is not None or text is None:
            return SourceResult(url, Freshness.FAILED, None, reason=reason or "fetch_failed")
        return SourceResult(url, Freshness.UNKNOWN, text)

    return list(await asyncio.gather(*(fetch_preview(handle) for handle in handles)))


async def fetch_recent_telegram_posts(
    handles: Sequence[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: TelegramConfig,
) -> list[TelegramPost]:
    """Page public previews backwards until posts leave the configured fresh window."""
    semaphore = asyncio.Semaphore(settings.concurrency)

    async def collect(handle: str) -> list[TelegramPost]:
        base_url = canonical_preview_url(handle)
        collected: list[TelegramPost] = []
        seen_ids: set[str] = set()
        request_url: str | None = base_url
        page_count = 0
        while request_url is not None and (
            settings.max_pages_per_channel is None or page_count < settings.max_pages_per_channel
        ):
            async with semaphore:
                text, reason, _ = await _read_document(
                    client,
                    request_url,
                    max_response_bytes=settings.max_response_bytes,
                    max_redirects=settings.max_redirects,
                    timeout_seconds=settings.timeout_seconds,
                )
            if reason is not None or text is None:
                break
            page_posts = parse_preview_posts(text, handle, now, settings.max_post_age_hours)
            new_posts = [post for post in page_posts if post.message_id not in seen_ids]
            if not new_posts:
                break
            for post in new_posts:
                seen_ids.add(post.message_id)
                collected.append(post)
            page_count += 1
            if (
                settings.max_pages_per_channel is not None
                and page_count >= settings.max_pages_per_channel
            ):
                break
            request_url = f"{base_url}?before={page_posts[-1].message_id}"
        return collected

    pages = await asyncio.gather(*(collect(handle) for handle in handles))
    return [post for page in pages for post in page]


def default_client(settings: SourcesConfig) -> httpx.AsyncClient:
    """Create the network client for concurrent subscription-document loading."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.timeout_seconds),
        follow_redirects=False,
        limits=httpx.Limits(
            max_connections=settings.concurrency,
            max_keepalive_connections=settings.concurrency,
        ),
        headers={"User-Agent": settings.user_agent},
    )
