from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

from bs4 import BeautifulSoup

from .models import TelegramPost

_HANDLE = r"[A-Za-z][A-Za-z0-9_]{4,31}"
_HANDLE_FULL = re.compile(rf"^{_HANDLE}$")
_AT_HANDLE = re.compile(rf"(?<![\w@])@(?P<handle>{_HANDLE})(?=$|[\s,;!?()\[\]{{}}])")
_PUBLIC_URL = re.compile(
    rf"(?<![\w.])(?:https?://)?(?:t\.me/(?:s/)?|telegram\.me/)"
    rf"(?!(?:joinchat|c)(?:[/?#\s]|$)|\+)(?P<handle>{_HANDLE})(?=$|[/?#\s,;!])",
    re.IGNORECASE,
)
_DEEP_LINK = re.compile(
    rf"tg://resolve\?[^\s#]*\bdomain=(?P<handle>{_HANDLE})(?=$|[&#\s])",
    re.IGNORECASE,
)
_PROFILE_URI = re.compile(r"(?P<uri>(?:vless|trojan|hy2|hysteria2)://[^\s<>\"']+)", re.IGNORECASE)


def _canonical_handle(value: str) -> str | None:
    handle = value.lower()
    if not _HANDLE_FULL.fullmatch(handle):
        return None
    return handle


def extract_telegram_handles(raw_text: str) -> set[str]:
    """Return explicit public Telegram usernames from a raw seed URI without logging it."""
    decoded = unquote(raw_text)
    handles: set[str] = set()
    for pattern in (_AT_HANDLE, _PUBLIC_URL, _DEEP_LINK):
        for match in pattern.finditer(decoded):
            handle = _canonical_handle(match.group("handle"))
            if handle is not None:
                handles.add(handle)
    return handles


def canonical_preview_url(handle: str) -> str:
    """Build the only public Telegram URL the collector is permitted to request."""
    canonical = _canonical_handle(handle)
    if canonical is None:
        raise ValueError("invalid public Telegram username")
    return f"https://t.me/s/{canonical}"


def _post_datetime(message: object) -> datetime | None:
    time_element = message.select_one("time[datetime]")
    if time_element is None:
        return None
    raw_value = time_element.get("datetime")
    if not isinstance(raw_value, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _message_id(message: object) -> str | None:
    value = message.get("data-post")
    if not isinstance(value, str) or "/" not in value:
        return None
    identifier = value.rsplit("/", 1)[-1]
    return identifier if identifier.isdigit() else None


def parse_preview_posts(
    html: str,
    handle: str,
    now: datetime,
    max_age_hours: int,
) -> list[TelegramPost]:
    """Parse dated, public preview posts in the configured trailing time window."""
    canonical = _canonical_handle(handle)
    if canonical is None:
        raise ValueError("invalid public Telegram username")
    if max_age_hours < 1 or max_age_hours > 72:
        raise ValueError("max_age_hours must be between 1 and 72")

    cutoff = now.astimezone(UTC) - timedelta(hours=max_age_hours)
    soup = BeautifulSoup(html, "html.parser")
    parsed_posts: list[TelegramPost] = []
    for message in soup.select(".tgme_widget_message"):
        published_at = _post_datetime(message)
        message_id = _message_id(message)
        text_element = message.select_one(".tgme_widget_message_text")
        if (
            published_at is None
            or message_id is None
            or text_element is None
            or published_at < cutoff
        ):
            continue
        text = text_element.get_text(" ", strip=True)
        hrefs = tuple(
            href
            for anchor in text_element.select("a[href]")
            if isinstance((href := anchor.get("href")), str)
        )
        parsed_posts.append(
            TelegramPost(
                handle=canonical,
                message_id=message_id,
                published_at=published_at.isoformat().replace("+00:00", "Z"),
                text=text,
                hrefs=hrefs,
            )
        )
    return parsed_posts


def _uri_candidates(value: str) -> Iterable[str]:
    for match in _PROFILE_URI.finditer(value):
        candidate = match.group("uri").rstrip(".,;!)]}")
        yield candidate


def extract_profile_uris(posts: Iterable[TelegramPost]) -> list[str]:
    """Extract only project-supported URI schemes, preserving first-seen order in memory."""
    seen: set[str] = set()
    extracted: list[str] = []
    for post in posts:
        for value in (post.text, *post.hrefs):
            for candidate in _uri_candidates(value):
                normalized = candidate.lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                extracted.append(candidate)
    return extracted
