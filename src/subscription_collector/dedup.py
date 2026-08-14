from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import Profile


def profile_fingerprint(profile: Profile) -> str:
    """Return a stable hash of security-significant data, excluding display/source metadata."""
    material = {
        "protocol": profile.protocol.value,
        "server": profile.server,
        "port": profile.port,
        "username": profile.username,
        "secret": profile.secret,
        "security": profile.security,
        "transport": profile.transport,
        "params": dict(sorted(profile.params.items())),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def deduplicate(profiles: Iterable[Profile]) -> list[Profile]:
    """Keep the first canonical instance of each semantic profile."""
    result: list[Profile] = []
    seen: set[str] = set()
    for profile in profiles:
        fingerprint = profile_fingerprint(profile)
        if fingerprint not in seen:
            seen.add(fingerprint)
            result.append(profile)
    return result
