from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import Profile

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _canonical_material(profile: Profile) -> dict[str, object]:
    return {
        "protocol": profile.protocol.value,
        "server": profile.server.lower(),
        "port": profile.port,
        "username": profile.username,
        "secret": profile.secret,
        "security": profile.security.lower(),
        "transport": profile.transport.lower(),
        "params": dict(sorted((key.lower(), value) for key, value in profile.params.items())),
    }


def profile_fingerprint(profile: Profile) -> str:
    """Return the exact connection identity without source or display metadata."""
    encoded = json.dumps(
        _canonical_material(profile),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def client_compatibility_key(profile: Profile) -> tuple[str, str, int, str]:
    """Return v2rayNG-style normalized endpoint/credential fields for safe grouping only."""
    credential = profile.secret if profile.secret is not None else profile.username or ""
    return (
        profile.protocol.value,
        profile.server.lower(),
        profile.port,
        credential.strip().lower(),
    )


def deduplicate(profiles: Iterable[Profile]) -> list[Profile]:
    """Remove cosmetic duplicates without collapsing profiles with distinct connection settings."""
    result: list[Profile] = []
    seen_exact: set[str] = set()
    for profile in profiles:
        fingerprint = profile_fingerprint(profile)
        if fingerprint in seen_exact:
            continue
        seen_exact.add(fingerprint)
        result.append(profile)
    return result


def compact_code(fingerprint: str) -> str:
    """Derive a stable six-character base62 code from the canonical SHA-256 digest."""
    value = int(fingerprint[:16], 16) % (len(_BASE62) ** 6)
    characters: list[str] = []
    for _ in range(6):
        value, remainder = divmod(value, len(_BASE62))
        characters.append(_BASE62[remainder])
    return "".join(reversed(characters))
