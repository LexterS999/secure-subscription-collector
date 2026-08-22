from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .models import Profile, Protocol

_ALIASES = {"hy2": "hysteria2"}
_SUPPORTED = {protocol.value for protocol in Protocol}
_HOST_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")


def _query(uri: str) -> dict[str, str]:
    return {
        key.lower(): value.strip()
        for key, value in parse_qsl(urlsplit(uri).query, keep_blank_values=True)
    }


def _valid_host(value: str | None) -> str | None:
    if not value:
        return None
    host = value.strip().strip("[]")
    if not host or not _HOST_PATTERN.fullmatch(host):
        return None
    return host.lower()


def _port(value: str | int | None) -> int | None:
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _uuid(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        candidate,
    ):
        return candidate
    return None


def _profile(
    *,
    protocol: Protocol,
    server: str | None,
    port: int | None,
    username: str | None,
    secret: str | None,
    security: str,
    transport: str,
    params: dict[str, str],
    source_url: str,
    uri: str,
) -> Profile | None:
    if server is None or port is None:
        return None
    try:
        return Profile(
            protocol=protocol,
            server=server,
            port=port,
            username=username,
            secret=secret,
            security=security.lower().strip(),
            transport=transport.lower().strip() or "tcp",
            params=params,
            source_url=source_url,
            original_uri=uri.split("#", 1)[0],
        )
    except ValueError:
        return None


def _standard_split(uri: str) -> tuple[object, dict[str, str], str | None, int | None]:
    parsed = urlsplit(uri)
    params = _query(uri)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed, params, _valid_host(parsed.hostname), _port(port)


def _parse_vless(uri: str, source_url: str) -> Profile | None:
    parsed, params, server, port = _standard_split(uri)
    return _profile(
        protocol=Protocol.VLESS,
        server=server,
        port=port,
        username=_uuid(unquote(parsed.username or "")),
        secret=None,
        security=params.get("security", "none"),
        transport=params.get("type", "tcp"),
        params=params,
        source_url=source_url,
        uri=uri,
    )


def _parse_trojan_like(uri: str, source_url: str, protocol: Protocol) -> Profile | None:
    parsed, params, server, port = _standard_split(uri)
    username = None
    secret = unquote(parsed.username or "")
    transport = params.get("type", "tcp")
    if protocol is Protocol.HYSTERIA2:
        transport = "udp"
    return _profile(
        protocol=protocol,
        server=server,
        port=port,
        username=username,
        secret=secret or None,
        security=params.get("security", "tls"),
        transport=transport,
        params=params,
        source_url=source_url,
        uri=uri,
    )


def parse_profile(uri: str, source_url: str) -> Profile | None:
    """Parse one approved URI scheme into a canonical local profile representation."""
    if not uri or any(ord(character) < 32 and character not in "\t\n\r" for character in uri):
        return None
    try:
        scheme = urlsplit(uri).scheme.lower()
    except ValueError:
        return None
    scheme = _ALIASES.get(scheme, scheme)
    if scheme not in _SUPPORTED:
        return None
    if scheme == Protocol.VLESS.value:
        return _parse_vless(uri, source_url)
    return _parse_trojan_like(uri, source_url, Protocol(scheme))
