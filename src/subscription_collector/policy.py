from __future__ import annotations

import base64
import binascii
import re
from uuid import UUID

from .models import Decision, Profile, Protocol

_AEAD_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
_ALLOWED_TRANSPORTS = {
    "tcp",
    "raw",
    "ws",
    "websocket",
    "grpc",
    "h2",
    "http",
    "httpupgrade",
    "xhttp",
    "quic",
    "udp",
}
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


def _require_tls_details(profile: Profile) -> str | None:
    if not profile.params.get("sni"):
        return "missing_sni"
    if not profile.params.get("fp"):
        return "missing_fingerprint"
    return None


def _secure_uri_profile(profile: Profile) -> Decision:
    if _has_insecure_flag(profile):
        return Decision(None, "insecure_flag")
    if profile.transport not in _ALLOWED_TRANSPORTS:
        return Decision(None, "unsupported_transport")
    if profile.protocol is Protocol.VLESS:
        if (
            not _valid_uuid(profile.username)
            or profile.params.get("encryption", "").lower() != "none"
        ):
            return Decision(None, "missing_required_secret")
        if profile.security == "reality":
            tls_reason = _require_tls_details(profile)
            if tls_reason:
                return Decision(None, tls_reason)
            if not _valid_reality_key(profile.params.get("pbk")):
                return Decision(None, "invalid_reality_key")
            return Decision(profile)
        if profile.security == "tls":
            return (
                Decision(None, tls_reason)
                if (tls_reason := _require_tls_details(profile))
                else Decision(profile)
            )
        return Decision(None, "missing_security")
    if profile.protocol is Protocol.VMESS:
        if not _valid_uuid(profile.username):
            return Decision(None, "missing_required_secret")
        if profile.security != "tls":
            return Decision(None, "missing_security")
        if profile.params.get("scy", "auto").lower() == "none":
            return Decision(None, "missing_security")
        return (
            Decision(None, tls_reason)
            if (tls_reason := _require_tls_details(profile))
            else Decision(profile)
        )
    if profile.protocol in {
        Protocol.TROJAN,
        Protocol.HYSTERIA2,
        Protocol.TUIC,
        Protocol.NAIVE,
        Protocol.ANYTLS,
        Protocol.JUICITY,
    }:
        if not profile.secret:
            return Decision(None, "missing_required_secret")
        if profile.protocol in {Protocol.TUIC, Protocol.JUICITY} and not _valid_uuid(
            profile.username
        ):
            return Decision(None, "missing_required_secret")
        if profile.security != "tls":
            return Decision(None, "missing_security")
        if not profile.params.get("sni"):
            return Decision(None, "missing_sni")
        if profile.protocol is Protocol.TROJAN and not profile.params.get("fp"):
            return Decision(None, "missing_fingerprint")
        return Decision(profile)
    return Decision(None, "unsupported_protocol")


def _secure_ss(profile: Profile) -> Decision:
    if not profile.secret:
        return Decision(None, "missing_required_secret")
    if profile.params.get("method", "").lower() not in _AEAD_METHODS:
        return Decision(None, "legacy_cipher")
    return Decision(profile)


def _secure_wireguard(profile: Profile) -> Decision:
    required = (profile.username, profile.params.get("publickey"), profile.params.get("address"))
    return Decision(profile) if all(required) else Decision(None, "missing_required_secret")


def _secure_mtproto(profile: Profile) -> Decision:
    secret = profile.secret or ""
    if not re.fullmatch(r"[0-9a-fA-F]{32}(?:[0-9a-fA-F]{2})?(?:[0-9a-fA-F]{30})?", secret):
        return Decision(None, "invalid_mtproto_secret")
    return Decision(profile)


def evaluate_strict_secure(profile: Profile) -> Decision:
    """Apply static security rules without contacting the profile endpoint."""
    if profile.protocol is Protocol.SS:
        return _secure_ss(profile)
    if profile.protocol is Protocol.WIREGUARD:
        return _secure_wireguard(profile)
    if profile.protocol is Protocol.MTPROTO:
        return _secure_mtproto(profile)
    return _secure_uri_profile(profile)
