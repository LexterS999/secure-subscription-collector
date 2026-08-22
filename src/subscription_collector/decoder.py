from __future__ import annotations

import base64
import binascii
from urllib.parse import urlsplit

SUPPORTED_SCHEMES = {"vless", "trojan", "hy2", "hysteria2"}


def _uri_lines(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for raw_line in text.removeprefix("\ufeff").replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        try:
            scheme = urlsplit(line).scheme.lower()
        except ValueError:
            continue
        if scheme in SUPPORTED_SCHEMES and line not in seen:
            seen.add(line)
            values.append(line)
    return values


def _decode_base64(value: str) -> str | None:
    compact = "".join(value.split())
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/="
    if not compact or any(character not in allowed for character in compact):
        return None
    try:
        padded = compact + "=" * (-len(compact) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return None


def extract_candidate_lines(source_text: str) -> list[str]:
    """Extract supported URI lines from plain text or exactly one base64 envelope."""
    direct = _uri_lines(source_text)
    if direct:
        return direct
    decoded = _decode_base64(source_text)
    return _uri_lines(decoded) if decoded is not None else []
