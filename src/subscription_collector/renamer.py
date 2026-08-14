from __future__ import annotations

from .dedup import compact_code
from .models import Profile, Protocol

_PROTOCOL_LABELS = {
    Protocol.VLESS: "VL",
    Protocol.TROJAN: "TR",
    Protocol.HYSTERIA2: "HY2",
    Protocol.TUIC: "TUIC",
}
_TRANSPORT_LABELS = {
    "raw": "TCP",
    "tcp": "TCP",
    "ws": "WS",
    "websocket": "WS",
    "grpc": "GRPC",
    "h2": "H2",
    "httpupgrade": "HUP",
    "xhttp": "XHTTP",
    "udp": "UDP",
}


def _display_transport(profile: Profile) -> str:
    if profile.protocol in {Protocol.HYSTERIA2, Protocol.TUIC}:
        return "UDP"
    return _TRANSPORT_LABELS.get(profile.transport.lower(), "TCP")


def render_named_uri(profile: Profile, fingerprint: str) -> str:
    """Attach a readable ASCII fragment accepted by standard Android URI importers."""
    label = "-".join(
        (
            _PROTOCOL_LABELS[profile.protocol],
            profile.security.upper(),
            _display_transport(profile),
            compact_code(fingerprint),
        )
    )
    return f"{profile.original_uri.split('#', 1)[0]}#{label}"
