from __future__ import annotations

import asyncio
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx

from .config_loader import SourcesConfig, TelegramConfig
from .models import Freshness, SourceResult, TelegramPost
from .telegram import canonical_preview_url, parse_preview_posts

ProgressCallback = Callable[[int, int], None]
PageProgressCallback = Callable[[int], None]

# Transient upstream answers worth one more attempt: rate limiting and the
# classic gateway/server hiccups. Deterministic failures never retry.
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class ChannelPreview:
    """Per-channel outcome of paging public previews within the fresh window."""

    handle: str
    available: bool
    posts: list[TelegramPost] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _DocumentOutcome:
    """Raw result of one document download attempt chain."""

    text: str | None = None
    reason: str | None = None
    last_modified: str | None = None
    retry_after: float | None = None


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


def _parse_retry_after(value: str | None) -> float | None:
    """Return the delay requested by a ``Retry-After`` header in whole seconds."""
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return None


def _per_request_timeout(settings_timeout: float, connect_timeout: float) -> httpx.Timeout:
    """Phase timeouts for a single request; the connect phase fails fast."""
    return httpx.Timeout(settings_timeout, connect=connect_timeout)


async def _read_document(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_response_bytes: int,
    max_redirects: int,
    timeout_seconds: float,
    connect_timeout_seconds: float,
) -> _DocumentOutcome:
    """Fetch one HTTPS document without following unsafe redirects.

    Returns a ``_DocumentOutcome``; ``text`` is set only when the reason is ``None``.
    """
    request_url = url
    try:
        for redirect_count in range(max_redirects + 1):
            response = await client.get(
                request_url,
                follow_redirects=False,
                timeout=_per_request_timeout(timeout_seconds, connect_timeout_seconds),
            )
            if response.is_redirect:
                location = response.headers.get("Location")
                if redirect_count == max_redirects:
                    return _DocumentOutcome(reason="too_many_redirects")
                if not location:
                    return _DocumentOutcome(reason="redirect_without_location")
                try:
                    location_parts = urlsplit(location)
                    if location_parts.scheme and not location_parts.netloc:
                        raise ValueError("redirect URL has no host")
                    next_url = str(response.url.join(location))
                    next_parts = urlsplit(next_url)
                except ValueError:
                    return _DocumentOutcome(reason="redirect_invalid_location")
                if next_parts.scheme != "https" or not next_parts.netloc:
                    return _DocumentOutcome(reason="redirect_non_https")
                if next_parts.username or next_parts.password:
                    return _DocumentOutcome(reason="redirect_credentials")
                request_url = next_url
                continue
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as error:
                status = error.response.status_code
                retryable = status in _RETRYABLE_STATUS_CODES
                return _DocumentOutcome(
                    reason=f"http_{status}",
                    retry_after=_parse_retry_after(error.response.headers.get("Retry-After"))
                    if retryable
                    else None,
                )
            content = response.content
            if len(content) > max_response_bytes:
                return _DocumentOutcome(reason="response_too_large")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return _DocumentOutcome(reason="invalid_utf8")
            return _DocumentOutcome(
                text, None, response.headers.get("Last-Modified")
            )
        return _DocumentOutcome(reason="too_many_redirects")
    except httpx.TimeoutException:
        return _DocumentOutcome(reason="timeout")
    except httpx.HTTPError as error:
        return _DocumentOutcome(reason=f"http_error:{type(error).__name__}")


def _is_retryable(outcome: _DocumentOutcome) -> bool:
    """Report whether one failed attempt deserves another one."""
    if outcome.reason is None:
        return False
    if outcome.reason.startswith("http_"):
        # Only transient statuses (429/5xx) are encoded this way.
        return True
    return outcome.reason == "timeout"


async def _read_document_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_response_bytes: int,
    max_redirects: int,
    timeout_seconds: float,
    connect_timeout_seconds: float,
    total_deadline_seconds: float,
    retries: int,
    retry_backoff_seconds: float,
) -> _DocumentOutcome:
    """Fetch one document under a hard total deadline with bounded transient retries.

    The deadline covers every attempt, redirect hop, and backoff sleep, so a
    slow-drip server can stall one source for at most ``total_deadline_seconds``
    instead of hanging forever between chunk timeouts.
    """
    try:
        async with asyncio.timeout(total_deadline_seconds):
            attempt = 0
            while True:
                outcome = await _read_document(
                    client,
                    url,
                    max_response_bytes=max_response_bytes,
                    max_redirects=max_redirects,
                    timeout_seconds=timeout_seconds,
                    connect_timeout_seconds=connect_timeout_seconds,
                )
                if outcome.reason is None or not _is_retryable(outcome):
                    return outcome
                attempt += 1
                if attempt > retries:
                    return outcome
                if outcome.retry_after is not None:
                    delay = outcome.retry_after
                else:
                    delay = retry_backoff_seconds * (2 ** (attempt - 1)) + random.uniform(
                        0, retry_backoff_seconds
                    )
                await asyncio.sleep(delay)
                continue
    except TimeoutError:
        return _DocumentOutcome(reason="deadline_exceeded")


async def _fetch_one(
    url: str,
    client: httpx.AsyncClient,
    now: datetime,
    settings: SourcesConfig,
    semaphore: asyncio.Semaphore,
) -> SourceResult:
    async with semaphore:
        outcome = await _read_document_with_retries(
            client,
            url,
            max_response_bytes=settings.max_response_bytes,
            max_redirects=settings.max_redirects,
            timeout_seconds=settings.timeout_seconds,
            connect_timeout_seconds=settings.connect_timeout_seconds,
            total_deadline_seconds=settings.total_deadline_seconds,
            retries=settings.retries,
            retry_backoff_seconds=settings.retry_backoff_seconds,
        )
    if outcome.reason is not None or outcome.text is None:
        return SourceResult(
            url, Freshness.FAILED, None, reason=outcome.reason or "fetch_failed"
        )

    modified = _parse_last_modified(outcome.last_modified)
    if modified is None:
        return SourceResult(url, Freshness.UNKNOWN, outcome.text, last_modified=None)
    age_seconds = (now.astimezone(UTC) - modified).total_seconds()
    if age_seconds > settings.max_age_hours * 3600:
        return SourceResult(url, Freshness.STALE, None, last_modified=modified.isoformat())
    return SourceResult(url, Freshness.RECENT, outcome.text, last_modified=modified.isoformat())


async def fetch_sources(
    urls: list[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: SourcesConfig,
    *,
    progress: ProgressCallback | None = None,
) -> list[SourceResult]:
    """Fetch subscription documents without contacting addresses contained in them."""
    semaphore = asyncio.Semaphore(settings.concurrency)
    total = len(urls)
    completed = 0

    async def tracked(url: str) -> SourceResult:
        nonlocal completed
        result = await _fetch_one(url, client, now, settings, semaphore)
        completed += 1
        if progress is not None:
            progress(completed, total)
        return result

    return list(await asyncio.gather(*(tracked(url) for url in urls)))


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
            outcome = await _read_document_with_retries(
                client,
                url,
                max_response_bytes=settings.max_response_bytes,
                max_redirects=settings.max_redirects,
                timeout_seconds=settings.timeout_seconds,
                connect_timeout_seconds=settings.connect_timeout_seconds,
                total_deadline_seconds=settings.total_deadline_seconds,
                retries=settings.retries,
                retry_backoff_seconds=settings.retry_backoff_seconds,
            )
        if outcome.reason is not None or outcome.text is None:
            return SourceResult(
                url, Freshness.FAILED, None, reason=outcome.reason or "fetch_failed"
            )
        return SourceResult(url, Freshness.UNKNOWN, outcome.text)

    return list(await asyncio.gather(*(fetch_preview(handle) for handle in handles)))


async def fetch_channel_posts(
    handles: Sequence[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: TelegramConfig,
    *,
    progress: PageProgressCallback | None = None,
) -> dict[str, ChannelPreview]:
    """Page public previews per handle until posts leave the fresh window.

    ``available`` reports whether at least one preview page was fetched, which
    distinguishes a transport failure from a healthy preview without fresh posts.
    Page count per channel is bounded by ``max_pages_per_channel`` and every page
    honors the shared total deadline, so one channel cannot stall the stage.
    """
    semaphore = asyncio.Semaphore(settings.concurrency)
    pages_completed = 0

    def page_done() -> None:
        nonlocal pages_completed
        pages_completed += 1
        if progress is not None:
            progress(pages_completed)

    async def collect(handle: str) -> ChannelPreview:
        base_url = canonical_preview_url(handle)
        collected: list[TelegramPost] = []
        seen_ids: set[str] = set()
        request_url: str | None = base_url
        page_count = 0
        available = False
        while request_url is not None and (
            settings.max_pages_per_channel is None or page_count < settings.max_pages_per_channel
        ):
            async with semaphore:
                outcome = await _read_document_with_retries(
                    client,
                    request_url,
                    max_response_bytes=settings.max_response_bytes,
                    max_redirects=settings.max_redirects,
                    timeout_seconds=settings.timeout_seconds,
                    connect_timeout_seconds=settings.connect_timeout_seconds,
                    total_deadline_seconds=settings.total_deadline_seconds,
                    retries=settings.retries,
                    retry_backoff_seconds=settings.retry_backoff_seconds,
                )
            page_done()
            if outcome.reason is not None or outcome.text is None:
                break
            available = True
            # HTML parsing is pure CPU work; keep the event loop free for
            # in-flight downloads by parsing off the loop thread.
            page_posts = await asyncio.to_thread(
                parse_preview_posts, outcome.text, handle, now, settings.max_post_age_hours
            )
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
        return ChannelPreview(handle=handle, available=available, posts=collected)

    pages = await asyncio.gather(*(collect(handle) for handle in handles))
    return {preview.handle.lower(): preview for preview in pages}


async def fetch_recent_telegram_posts(
    handles: Sequence[str],
    client: httpx.AsyncClient,
    now: datetime,
    settings: TelegramConfig,
) -> list[TelegramPost]:
    """Collect fresh-window posts for handles in the given order."""
    previews = await fetch_channel_posts(handles, client, now, settings)
    return [post for handle in handles for post in previews[handle.lower()].posts]


def default_client(settings: SourcesConfig) -> httpx.AsyncClient:
    """Create the network client for concurrent subscription-document loading."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            settings.timeout_seconds, connect=settings.connect_timeout_seconds
        ),
        follow_redirects=False,
        limits=httpx.Limits(
            max_connections=settings.concurrency,
            max_keepalive_connections=settings.concurrency,
        ),
        headers={"User-Agent": settings.user_agent},
    )
