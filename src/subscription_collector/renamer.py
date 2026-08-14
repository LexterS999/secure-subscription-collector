from __future__ import annotations

from urllib.parse import quote

from .models import Profile


def _display_security(profile: Profile) -> str:
    if profile.protocol.value == "ss":
        return profile.params.get("method", "aead").upper()
    return profile.security.upper()


def _display_transport(profile: Profile) -> str:
    return profile.transport.upper() if profile.transport else "TCP"


def render_named_uri(profile: Profile, fingerprint: str) -> str:
    """Attach a deterministic display-only label without exposing secret fields."""
    label = " • ".join(
        (
            profile.protocol.value.upper(),
            _display_security(profile),
            _display_transport(profile),
            profile.server,
            str(profile.port),
            fingerprint[:6].upper(),
        )
    )
    return f"{profile.original_uri.split('#', 1)[0]}#{quote(label, safe='')}"
