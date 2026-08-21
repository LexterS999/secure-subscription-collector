"""Profile deduplication following the v2rayNG client behavior.

v2rayNG identifies a profile by its effective outbound configuration: protocol,
address, port, credential, and every stream setting the client actually maps
(query order, display names, and unknown vendor parameters are irrelevant).
Transport aliases collapse as well, so ``ws``/``websocket`` and ``tcp``/``raw``
denote one configuration. Two profiles are duplicates exactly when their
canonical outbound material is equal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import Profile

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_TRANSPORT_ALIASES = {"websocket": "ws", "raw": "tcp"}

_TRUE_VALUES = {"1", "true", "yes"}


def _normalized_transport(profile: Profile) -> str:
    transport = profile.transport.lower()
    return _TRANSPORT_ALIASES.get(transport, transport)


def _insecure_flag(profile: Profile) -> bool:
    return any(
        profile.params.get(key, "").lower() in _TRUE_VALUES for key in ("allowinsecure", "insecure")
    )


def _split_alpn(value: str) -> list[str]:
    return [token.strip() for token in value.split(",") if token.strip()]


def _stream_material(profile: Profile) -> dict[str, object]:
    """Stream settings exactly as Android clients map them from share links."""
    params = profile.params
    network = _normalized_transport(profile)
    material: dict[str, object] = {
        "network": network,
        "security": profile.security.lower(),
        "sni": params.get("sni", ""),
        "fingerprint": params.get("fp", ""),
        "alpn": _split_alpn(params.get("alpn", "")),
        "allowInsecure": _insecure_flag(profile),
    }
    if network == "ws":
        material["path"] = params.get("path", "/")
        material["host"] = params.get("host", "")
    elif network == "grpc":
        material["serviceName"] = params.get("servicename", "")
        material["authority"] = params.get("authority", "")
        multi = params.get("mode") == "multi" or params.get("multimode") == "true"
        material["mode"] = "multi" if multi else "gun"
    elif network in {"h2", "xhttp"}:
        material["host"] = params.get("host", "")
        material["path"] = params.get("path", "")
        if network == "xhttp":
            material["mode"] = params.get("mode", "auto")
            material["extra"] = params.get("extra", "")
    elif network == "httpupgrade":
        material["path"] = params.get("path", "/")
        material["host"] = params.get("host", "")
    if profile.security == "reality":
        material["publicKey"] = params.get("pbk", "")
        material["shortId"] = params.get("sid", "")
        material["spiderX"] = params.get("spx", "")
    return material


def _canonical_material(profile: Profile) -> dict[str, object]:
    material: dict[str, object] = {
        "protocol": profile.protocol.value,
        "address": profile.server.lower(),
        "port": profile.port,
        "credential": (profile.username or profile.secret or ""),
    }
    if profile.protocol.value == "vless":
        material["encryption"] = profile.params.get("encryption", "none").lower()
        material["flow"] = profile.params.get("flow", "")
        material.update(_stream_material(profile))
    elif profile.protocol.value == "trojan":
        material.update(_stream_material(profile))
    else:
        material["network"] = "quic"
        material["obfs"] = profile.params.get("obfs", "")
        material["obfsPassword"] = profile.params.get("obfs-password", "")
        material["ports"] = profile.params.get("mport") or profile.params.get("ports") or ""
        material["sni"] = profile.params.get("sni", "")
        material["fingerprint"] = profile.params.get("fp", "")
        material["alpn"] = _split_alpn(profile.params.get("alpn", ""))
        material["allowInsecure"] = _insecure_flag(profile)
    return material


def profile_fingerprint(profile: Profile) -> str:
    """Return the stable identity of the effective outbound configuration."""
    encoded = json.dumps(
        _canonical_material(profile),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def client_compatibility_key(profile: Profile) -> tuple[str, str, int, str]:
    """Return coarse endpoint/credential fields for diagnostics only."""
    credential = profile.secret if profile.secret is not None else profile.username or ""
    return (
        profile.protocol.value,
        profile.server.lower(),
        profile.port,
        credential.strip().lower(),
    )


def deduplicate(profiles: Iterable[Profile]) -> list[Profile]:
    """Keep the first profile of every distinct outbound configuration."""
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
    """Derive a stable six-character base62 code from the canonical digest."""
    value = int(hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16], 16) % (
        len(_BASE62) ** 6
    )
    characters: list[str] = []
    for _ in range(6):
        value, remainder = divmod(value, len(_BASE62))
        characters.append(_BASE62[remainder])
    return "".join(reversed(characters))
