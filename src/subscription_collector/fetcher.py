from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx

from .models import Freshness, SourceResult

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_SOURCE_CONCURRENCY = 32


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


async def _fetch_one(
    url: str,
    client: httpx.AsyncClient,
    now: datetime,
    max_age_hours: int,
    semaphore: asyncio.Semaphore,
) -> SourceResult:
    async with semaphore:
        try:
            request_url = url
            for redirect_count in range(MAX_REDIRECTS + 1):
                response = await client.get(request_url, follow_redirects=False)
                if response.is_redirect:
                    location = response.headers.get("Location")
                    if redirect_count == MAX_REDIRECTS:
                        return SourceResult(
                            url, Freshness.FAILED, None, reason="too_many_redirects"
                        )
                    if not location:
                        return SourceResult(
                            url, Freshness.FAILED, None, reason="redirect_without_location"
                        )
                    try:
                        location_parts = urlsplit(location)
                        if location_parts.scheme and not location_parts.netloc:
                            raise ValueError("redirect URL has no host")
                        next_url = str(response.url.join(location))
                        next_parts = urlsplit(next_url)
                    except ValueError:
                        return SourceResult(
                            url, Freshness.FAILED, None, reason="redirect_invalid_location"
                        )
                    if next_parts.scheme != "https" or not next_parts.netloc:
                        return SourceResult(
                            url, Freshness.FAILED, None, reason="redirect_non_https"
                        )
                    if next_parts.username or next_parts.password:
                        return SourceResult(
                            url, Freshness.FAILED, None, reason="redirect_credentials"
                        )
                    request_url = next_url
                    continue
                response.raise_for_status()
                content = response.content
                if len(content) > MAX_RESPONSE_BYTES:
                    return SourceResult(url, Freshness.FAILED, None, reason="response_too_large")
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    return SourceResult(url, Freshness.FAILED, None, reason="invalid_utf8")
                break
            else:
                return SourceResult(url, Freshness.FAILED, None, reason="too_many_redirects")
        except httpx.TimeoutException:
            return SourceResult(url, Freshness.FAILED, None, reason="timeout")
        except httpx.HTTPError as error:
            return SourceResult(
                url, Freshness.FAILED, None, reason=f"http_error:{type(error).__name__}"
            )

    raw_header = response.headers.get("Last-Modified")
    modified = _parse_last_modified(raw_header)
    if modified is None:
        return SourceResult(url, Freshness.UNKNOWN, text, last_modified=None)
    age_seconds = (now.astimezone(UTC) - modified).total_seconds()
    if age_seconds > max_age_hours * 3600:
        return SourceResult(url, Freshness.STALE, None, last_modified=modified.isoformat())
    return SourceResult(url, Freshness.RECENT, text, last_modified=modified.isoformat())


async def fetch_sources(
    urls: list[str],
    client: httpx.AsyncClient,
    now: datetime,
    max_age_hours: int = 72,
    *,
    concurrency: int = DEFAULT_SOURCE_CONCURRENCY,
) -> list[SourceResult]:
    """Fetch subscription documents without contacting addresses contained in them."""
    if max_age_hours < 1:
        raise ValueError("max_age_hours must be at least one")
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    semaphore = asyncio.Semaphore(concurrency)
    return list(
        await asyncio.gather(
            *(_fetch_one(url, client, now, max_age_hours, semaphore) for url in urls)
        )
    )


def default_client(concurrency: int = DEFAULT_SOURCE_CONCURRENCY) -> httpx.AsyncClient:
    """Create the network client for concurrent subscription-document loading."""
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    return httpx.AsyncClient(
        timeout=httpx.Timeout(20.0),
        follow_redirects=False,
        limits=httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        ),
        headers={"User-Agent": "secure-subscription-collector/0.1"},
    )
