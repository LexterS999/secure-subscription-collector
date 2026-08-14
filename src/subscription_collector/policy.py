from __future__ import annotations

import base64
import binascii
from uuid import UUID

from .models import Decision, Profile, Protocol

_ALLOWED_TRANSPORTS = {"tcp", "raw", "ws", "websocket", "grpc", "h2", "httpupgrade", "xhttp", "udp"}
_TRUE_VALUES = {"1", "true", "yes"}


def _has_insecure_flag(profile: Profile) -> bool:
    return any(
        profile.params.get(key, "").lower() in _TRUE_VALUES for key in ("allowinsecure", "insecure")
    )


def _valid_uuid(value: str | None) -> bool:
    try:
        UUID(value or "")
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def _valid_reality_key(value: str | None) -> bool:
    if not value:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 32


def _require_sni(profile: Profile) -> str | None:
    return None if profile.params.get("sni") else "missing_sni"


def _require_tls_details(profile: Profile) -> str | None:
    if not profile.params.get("sni"):
        return "missing_sni"
    if not profile.params.get("fp"):
        return "missing_fingerprint"
    return None


def _validate_vless(profile: Profile) -> Decision:
    if not _valid_uuid(profile.username) or profile.params.get("encryption", "").lower() != "none":
        return Decision(None, "missing_required_secret")
    if profile.security == "reality":
        if reason := _require_tls_details(profile):
            return Decision(None, reason)
        if not _valid_reality_key(profile.params.get("pbk")):
            return Decision(None, "invalid_reality_key")
        return Decision(profile)
    if profile.security == "tls":
        return (
            Decision(None, reason)
            if (reason := _require_tls_details(profile))
            else Decision(profile)
        )
    return Decision(None, "missing_security")


def _validate_trojan(profile: Profile) -> Decision:
    if not profile.secret:
        return Decision(None, "missing_required_secret")
    if profile.security != "tls":
        return Decision(None, "missing_security")
    return (
        Decision(None, reason) if (reason := _require_tls_details(profile)) else Decision(profile)
    )


def _validate_hysteria2(profile: Profile) -> Decision:
    if not profile.secret:
        return Decision(None, "missing_required_secret")
    if profile.security != "tls":
        return Decision(None, "missing_security")
    return Decision(None, reason) if (reason := _require_sni(profile)) else Decision(profile)


def _validate_tuic(profile: Profile) -> Decision:
    if profile.params.get("version", "5") != "5":
        return Decision(None, "unsupported_tuic_version")
    if not _valid_uuid(profile.username) or not profile.secret:
        return Decision(None, "missing_required_secret")
    if profile.security != "tls":
        return Decision(None, "missing_security")
    return Decision(None, reason) if (reason := _require_sni(profile)) else Decision(profile)


def evaluate_strict_secure(profile: Profile) -> Decision:
    """Apply static Strict Secure requirements without contacting the profile endpoint."""
    if _has_insecure_flag(profile):
        return Decision(None, "insecure_flag")
    if profile.transport not in _ALLOWED_TRANSPORTS:
        return Decision(None, "unsupported_transport")
    if profile.protocol is Protocol.VLESS:
        return _validate_vless(profile)
    if profile.protocol is Protocol.TROJAN:
        return _validate_trojan(profile)
    if profile.protocol is Protocol.HYSTERIA2:
        return _validate_hysteria2(profile)
    if profile.protocol is Protocol.TUIC:
        return _validate_tuic(profile)
    return Decision(None, "unsupported_protocol")
