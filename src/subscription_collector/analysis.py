"""Deep static analysis of parsed profiles beyond the strict security policy.

The checks mirror constraints enforced by Android proxy clients (v2rayNG and
compatible importers): known TLS fingerprints, well-formed transport options,
consistent Reality parameters, and valid Hysteria2 obfuscation settings.
Profiles that cannot be represented faithfully by such clients are rejected
before publication so the output contains only usable configurations.
"""

from __future__ import annotations

import re

from .models import Decision, Profile, Protocol

_KNOWN_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
}

_KNOWN_ALPN_TOKENS = {"h2", "http/1.1", "h3"}

_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}

_GRPC_MODES = {"gun", "multi"}

_SUPPORTED_FLOWS = {"xtls-rprx-vision"}

_SHORT_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{0,16}$")

_PORT_RANGE_PATTERN = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5}){0,1})*$")

_DOMAIN_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def _split_alpn(value: str) -> list[str]:
    return [token.strip() for token in value.split(",") if token.strip()]


def _check_fingerprint(profile: Profile) -> str | None:
    fingerprint = profile.params.get("fp", "").strip().lower()
    if fingerprint and fingerprint not in _KNOWN_FINGERPRINTS:
        return "unknown_fingerprint"
    return None


def _check_alpn(profile: Profile) -> str | None:
    alpn = profile.params.get("alpn")
    if alpn is not None and any(
        token.lower() not in _KNOWN_ALPN_TOKENS for token in _split_alpn(alpn)
    ):
        return "invalid_alpn"
    return None


def _check_transport_options(profile: Profile) -> str | None:
    transport = profile.transport.lower()
    params = profile.params
    if transport in {"ws", "websocket"}:
        path = params.get("path", "/")
        if path and not path.startswith("/"):
            return "invalid_ws_path"
    elif transport == "grpc":
        mode = params.get("mode", "").strip().lower()
        if mode and mode not in _GRPC_MODES:
            return "invalid_grpc_mode"
    elif transport == "xhttp":
        mode = params.get("mode", "").strip().lower()
        if mode and mode not in _XHTTP_MODES:
            return "invalid_xhttp_mode"
    return None


def _check_reality(profile: Profile) -> str | None:
    if profile.security != "reality":
        return None
    params = profile.params
    short_id = params.get("sid", "").strip()
    if short_id and not _SHORT_ID_PATTERN.fullmatch(short_id):
        return "invalid_short_id"
    spider_x = params.get("spx", "").strip()
    if spider_x and not spider_x.startswith("/"):
        return "invalid_spider_x"
    server_name = params.get("sni", profile.server).strip()
    if not _DOMAIN_PATTERN.fullmatch(server_name) or not any(
        character.isalpha() for character in server_name
    ):
        return "invalid_reality_sni"
    return None


def _check_hysteria2(profile: Profile) -> str | None:
    if profile.protocol is not Protocol.HYSTERIA2:
        return None
    params = profile.params
    obfs = params.get("obfs", "").strip().lower()
    if obfs and obfs != "none":
        if obfs != "salamander":
            return "unsupported_obfs"
        if not params.get("obfs-password"):
            return "missing_obfs_password"
    ports = params.get("mport") or params.get("ports") or ""
    if ports.strip() and not _PORT_RANGE_PATTERN.fullmatch(ports.strip()):
        return "invalid_port_range"
    return None


def _check_flow(profile: Profile) -> str | None:
    if profile.protocol is not Protocol.VLESS:
        return None
    flow = profile.params.get("flow", "").strip().lower()
    if not flow:
        return None
    if flow not in _SUPPORTED_FLOWS:
        return "unsupported_flow"
    transport = profile.transport.lower()
    if transport not in {"tcp", "raw"} or profile.security not in {"tls", "reality"}:
        return "incompatible_flow"
    return None


_CHECKS = (
    _check_fingerprint,
    _check_alpn,
    _check_transport_options,
    _check_reality,
    _check_hysteria2,
    _check_flow,
)


def analyze_profile(profile: Profile) -> Decision:
    """Run the deep client-compatibility checks over one parsed profile."""
    for check in _CHECKS:
        reason = check(profile)
        if reason is not None:
            return Decision(None, reason)
    return Decision(profile)
