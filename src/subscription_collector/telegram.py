from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from html import unescape
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
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9_+/=-]{16,}")
_MAX_BASE64_INPUT_BYTES = 1_048_576


def _canonical_handle(value: str) -> str | None:
    handle = value.lower()
    if not _HANDLE_FULL.fullmatch(handle):
        return None
    return handle


def extract_telegram_handles(raw_text: str) -> set[str]:
    """Return explicit public Telegram usernames from a raw seed URI without logging it."""
    decoded = unescape(unquote(raw_text))
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


def _parse_iso_datetime(raw_value: object) -> datetime | None:
    if not isinstance(raw_value, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _parse_unix_datetime(raw_value: object) -> datetime | None:
    if not isinstance(raw_value, str) or not raw_value.isdigit() or len(raw_value) not in {10, 13}:
        return None
    seconds = int(raw_value) / (1000 if len(raw_value) == 13 else 1)
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _post_datetime(message: object) -> datetime | None:
    time_element = message.select_one("time[datetime]")
    candidates: list[object] = []
    if time_element is not None:
        candidates.append(time_element.get("datetime"))
    candidates.extend(message.get(attribute) for attribute in ("data-datetime", "data-date"))
    timestamp_candidates = [message.get("data-timestamp")]
    date_element = message.select_one(".tgme_widget_message_date")
    if date_element is not None:
        candidates.extend(
            date_element.get(attribute)
            for attribute in ("datetime", "data-datetime", "title")
        )
        timestamp_candidates.append(date_element.get("data-timestamp"))
    for candidate in candidates:
        if (parsed := _parse_iso_datetime(candidate)) is not None:
            return parsed
    for candidate in timestamp_candidates:
        if (parsed := _parse_unix_datetime(candidate)) is not None:
            return parsed
    return None


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
            value
            for element in text_element.select(
                "[href], [data-url], [data-href], [data-telegram-url]"
            )
            for attribute in ("href", "data-url", "data-href", "data-telegram-url")
            if isinstance((value := element.get(attribute)), str)
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


def _strict_base64_text(value: str) -> str | None:
    token = value.strip()
    if len(token) > _MAX_BASE64_INPUT_BYTES or not _BASE64_TOKEN.fullmatch(token):
        return None
    unpadded = token.rstrip("=")
    if not unpadded or "=" in unpadded:
        return None
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    canonical = base64.b64encode(decoded, altchars=b"-_").decode("ascii").rstrip("=")
    if canonical != unpadded.replace("+", "-").replace("/", "_"):
        return None
    return text


def _uri_candidates(value: str) -> Iterable[str]:
    normalized = unescape(unquote(value))
    for candidate_text in (normalized, _strict_base64_text(normalized)):
        if candidate_text is None:
            continue
        for match in _PROFILE_URI.finditer(candidate_text):
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
