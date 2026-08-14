from __future__ import annotations

import base64
import binascii
from urllib.parse import urlsplit

from .models import Protocol

SUPPORTED_SCHEMES = {protocol.value for protocol in Protocol} | {"hy2", "wg", "tg"}
REJECTED_SCHEMES = {
    "socks",
    "socks4",
    "socks5",
    "http",
    "https",
    "ssr",
    "brook",
    "snell",
    "mieru",
}
KNOWN_SCHEMES = SUPPORTED_SCHEMES | REJECTED_SCHEMES


def _uri_lines(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for raw_line in text.removeprefix("\ufeff").replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        scheme = urlsplit(line).scheme.lower()
        if scheme in KNOWN_SCHEMES and line not in seen:
            seen.add(line)
            values.append(line)
    return values


def _decode_base64(value: str) -> str | None:
    compact = "".join(value.split())
    if not compact or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/="
        for character in compact
    ):
        return None
    try:
        padded = compact + "=" * (-len(compact) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return None


def extract_candidate_lines(source_text: str) -> list[str]:
    """Extract known URI lines from plain text or exactly one base64 envelope."""
    direct = _uri_lines(source_text)
    if direct:
        return direct
    decoded = _decode_base64(source_text)
    return _uri_lines(decoded) if decoded is not None else []
