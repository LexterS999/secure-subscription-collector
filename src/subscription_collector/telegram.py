from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from html import unescape
from urllib.parse import parse_qsl, unquote, urlsplit

from bs4 import BeautifulSoup, Tag

from .models import TelegramPost

_HANDLE = r"[A-Za-z][A-Za-z0-9_]{4,31}"
_HANDLE_FULL = re.compile(rf"^{_HANDLE}$")
_AT_HANDLE = re.compile(rf"(?<![\w@])@(?P<handle>{_HANDLE})(?=$|[\s,;!?()\[\]{{}}])")
_PUBLIC_URL = re.compile(
    rf"(?<![\w.])(?:https?://)?(?:t\.me/(?:s/)?|telegram\.me/|telegram\.dog/(?:s/)?|telesco\.pe/)"
    rf"(?!(?:joinchat|c)(?:[/?#\s]|$)|\+)(?P<handle>{_HANDLE})(?=$|[/?#\s,;!])",
    re.IGNORECASE,
)
_DEEP_LINK = re.compile(
    rf"(?:tg|telegram)://resolve\?[^\s#]*\bdomain=(?P<handle>{_HANDLE})(?=$|[&#\s])",
    re.IGNORECASE,
)
_PROFILE_URI = re.compile(r"(?P<uri>(?:vless|trojan|hy2|hysteria2)://[^\s<>\"']+)", re.IGNORECASE)
_GENERIC_PROFILE_URI = re.compile(
    r"(?P<uri>(?!(?:https?|tg|telegram)://)[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s<>\"']+)",
    re.IGNORECASE,
)
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9_+/=-]{16,}")
_EMBEDDED_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_+/=-])([A-Za-z0-9_+/=-]{24,})(?![A-Za-z0-9_+/=-])"
)
_DATEISH_KEY = re.compile(r"(?:date|time|timestamp)", re.IGNORECASE)
_ISO_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")
_UNIX_TEXT = re.compile(r"(?<!\d)(\d{10}|\d{13})(?!\d)")
_MAX_BASE64_INPUT_BYTES = 1_048_576
_ATTRIBUTE_NAMES = (
    "href",
    "data-url",
    "data-href",
    "data-telegram-url",
    "data-obfuscated-url",
    "data-link",
)
_TEXT_SELECTORS = (
    ".tgme_widget_message_text",
    ".tgme_widget_message_caption",
    ".js-message_text",
    "pre",
    "code",
    "blockquote",
)


def _canonical_handle(value: str) -> str | None:
    handle = value.lower()
    if not _HANDLE_FULL.fullmatch(handle):
        return None
    return handle


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


def _decoded_text_variants(value: str, *, max_depth: int = 2) -> Iterator[str]:
    queue: list[tuple[str, int]] = [(unescape(unquote(value)), 0)]
    seen: set[str] = set()
    while queue:
        candidate, depth = queue.pop(0)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        yield candidate
        if depth >= max_depth:
            continue

        try:
            parsed = urlsplit(candidate)
        except ValueError:
            parsed = None
        if parsed is not None:
            component_candidates = [parsed.path, parsed.fragment, parsed.query]
            component_candidates.extend(
                value for _, value in parse_qsl(parsed.query, keep_blank_values=True)
            )
            if parsed.fragment:
                fragment_query = parsed.fragment.split("?", 1)
                if len(fragment_query) == 2:
                    component_candidates.extend(
                        value for _, value in parse_qsl(fragment_query[1], keep_blank_values=True)
                    )
            for component in component_candidates:
                normalized = unescape(unquote(component))
                if normalized and normalized not in seen:
                    queue.append((normalized, depth + 1))

        if (decoded := _strict_base64_text(candidate)) is not None and decoded not in seen:
            queue.append((decoded, depth + 1))
        for token in _EMBEDDED_BASE64_TOKEN.findall(candidate):
            decoded_token = _strict_base64_text(token)
            if decoded_token is not None and decoded_token not in seen:
                queue.append((decoded_token, depth + 1))


def extract_telegram_handles(raw_text: str) -> set[str]:
    """Return explicit public Telegram usernames from a raw seed URI without logging it."""
    handles: set[str] = set()
    for decoded in _decoded_text_variants(raw_text):
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


def _parse_textual_datetime(raw_value: object) -> datetime | None:
    if not isinstance(raw_value, str):
        return None
    if (parsed := _parse_iso_datetime(raw_value)) is not None:
        return parsed
    for match in _ISO_TEXT.finditer(raw_value):
        if (parsed := _parse_iso_datetime(match.group(0))) is not None:
            return parsed
    for match in _UNIX_TEXT.finditer(raw_value):
        if (parsed := _parse_unix_datetime(match.group(1))) is not None:
            return parsed
    return None


def _flatten_attr_values(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str):
                yield item


def _date_candidates(message: Tag) -> Iterator[str]:
    time_element = message.select_one("time[datetime]")
    if time_element is not None:
        for value in _flatten_attr_values(time_element.get("datetime")):
            yield value

    for tag in (message, *message.find_all(True)):
        for attribute, raw_value in tag.attrs.items():
            if not _DATEISH_KEY.search(attribute):
                continue
            yield from _flatten_attr_values(raw_value)
        if tag.name in {"time", "script"}:
            text_value = tag.get_text(" ", strip=True)
            if text_value:
                yield text_value
        for attribute in ("title", "aria-label"):
            if isinstance((value := tag.get(attribute)), str):
                yield value


def _post_datetime(message: Tag) -> datetime | None:
    for candidate in _date_candidates(message):
        if (parsed := _parse_textual_datetime(candidate)) is not None:
            return parsed
    return None


def _message_id(message: Tag) -> str | None:
    value = message.get("data-post")
    if not isinstance(value, str) or "/" not in value:
        return None
    identifier = value.rsplit("/", 1)[-1]
    return identifier if identifier.isdigit() else None


def _message_text(message: Tag) -> str:
    segments: list[str] = []
    seen: set[str] = set()
    for selector in _TEXT_SELECTORS:
        for element in message.select(selector):
            text = element.get_text(" ", strip=True)
            if text and text not in seen:
                seen.add(text)
                segments.append(text)
    if segments:
        return " ".join(segments)
    return message.get_text(" ", strip=True)


def _message_hrefs(message: Tag) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    selector = ", ".join(f"[{attribute}]" for attribute in _ATTRIBUTE_NAMES)
    for element in message.select(selector):
        for attribute in _ATTRIBUTE_NAMES:
            value = element.get(attribute)
            if isinstance(value, str) and value not in seen:
                seen.add(value)
                values.append(value)
    return tuple(values)


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
        text = _message_text(message)
        if published_at is None or message_id is None or not text or published_at < cutoff:
            continue
        parsed_posts.append(
            TelegramPost(
                handle=canonical,
                message_id=message_id,
                published_at=published_at.isoformat().replace("+00:00", "Z"),
                text=text,
                hrefs=_message_hrefs(message),
            )
        )
    return parsed_posts


def _uri_candidates(value: str, *, supported_only: bool) -> Iterator[str]:
    pattern = _PROFILE_URI if supported_only else _GENERIC_PROFILE_URI
    for candidate_text in _decoded_text_variants(value):
        for match in pattern.finditer(candidate_text):
            candidate = match.group("uri").rstrip(".,;!)]}\"'")
            if candidate:
                yield candidate


def _extract_uris(posts: Iterable[TelegramPost], *, supported_only: bool) -> list[str]:
    seen: set[str] = set()
    extracted: list[str] = []
    for post in posts:
        for value in (post.text, *post.hrefs):
            for candidate in _uri_candidates(value, supported_only=supported_only):
                normalized = candidate.lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                extracted.append(candidate)
    return extracted


def extract_profile_uris(posts: Iterable[TelegramPost]) -> list[str]:
    """Extract only project-supported URI schemes, preserving first-seen order in memory."""
    return _extract_uris(posts, supported_only=True)


def extract_candidate_profile_uris(posts: Iterable[TelegramPost]) -> list[str]:
    """Extract all non-web URI candidates to measure channel signal-vs-noise quality."""
    return _extract_uris(posts, supported_only=False)
