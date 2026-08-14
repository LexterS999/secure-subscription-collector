from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .models import Profile, Protocol

_ALIASES = {"hy2": "hysteria2", "wg": "wireguard", "tg": "mtproto"}
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
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", candidate
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


def _parse_vmess(uri: str, source_url: str) -> Profile | None:
    payload = uri.split("://", 1)[1].split("#", 1)[0].strip()
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
        data = json.loads(decoded)
    except (UnicodeDecodeError, binascii.Error, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    params = {
        str(key).lower(): str(value).strip()
        for key, value in data.items()
        if isinstance(key, str) and value is not None
    }
    tls = params.get("tls", "").lower()
    security = "tls" if tls in {"tls", "1", "true"} else "none"
    return _profile(
        protocol=Protocol.VMESS,
        server=_valid_host(params.get("add")),
        port=_port(params.get("port")),
        username=_uuid(params.get("id")),
        secret=None,
        security=security,
        transport=params.get("net", "tcp"),
        params=params,
        source_url=source_url,
        uri=uri,
    )


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
    secret = unquote(parsed.username or "")
    username = None
    if protocol in {Protocol.TUIC, Protocol.JUICITY}:
        username = _uuid(unquote(parsed.username or ""))
        secret = unquote(parsed.password or "")
    security = params.get("security", "tls")
    return _profile(
        protocol=protocol,
        server=server,
        port=port,
        username=username,
        secret=secret or None,
        security=security,
        transport=params.get("type", "tcp"),
        params=params,
        source_url=source_url,
        uri=uri,
    )


def _parse_ss(uri: str, source_url: str) -> Profile | None:
    parsed, params, server, port = _standard_split(uri)
    raw_username = unquote(parsed.username or "")
    method = raw_username.lower()
    password = unquote(parsed.password or "")
    if not password and raw_username:
        try:
            decoded = base64.urlsafe_b64decode(
                raw_username + "=" * (-len(raw_username) % 4)
            ).decode("utf-8")
            method, password = decoded.split(":", 1)
            method = method.lower()
        except (UnicodeDecodeError, binascii.Error, ValueError):
            return None
    if not method or not password:
        return None
    params = {**params, "method": method}
    return _profile(
        protocol=Protocol.SS,
        server=server,
        port=port,
        username=method,
        secret=password,
        security=method,
        transport="tcp",
        params=params,
        source_url=source_url,
        uri=uri,
    )


def _parse_wireguard(uri: str, source_url: str) -> Profile | None:
    parsed, params, server, port = _standard_split(uri)
    private_key = unquote(parsed.username or "")
    return _profile(
        protocol=Protocol.WIREGUARD,
        server=server,
        port=port,
        username=private_key or None,
        secret=None,
        security="wireguard",
        transport="udp",
        params=params,
        source_url=source_url,
        uri=uri,
    )


def _parse_mtproto(uri: str, source_url: str) -> Profile | None:
    params = _query(uri)
    return _profile(
        protocol=Protocol.MTPROTO,
        server=_valid_host(params.get("server")),
        port=_port(params.get("port")),
        username=None,
        secret=params.get("secret"),
        security="mtproto",
        transport="tcp",
        params=params,
        source_url=source_url,
        uri=uri,
    )


def parse_profile(uri: str, source_url: str) -> Profile | None:
    """Parse a declared URI scheme into a canonical local representation."""
    if not uri or any(ord(character) < 32 and character not in "\t\n\r" for character in uri):
        return None
    try:
        scheme = urlsplit(uri).scheme.lower()
    except ValueError:
        return None
    scheme = _ALIASES.get(scheme, scheme)
    if scheme not in _SUPPORTED:
        return None
    if scheme == Protocol.VMESS.value:
        return _parse_vmess(uri, source_url)
    if scheme == Protocol.VLESS.value:
        return _parse_vless(uri, source_url)
    if scheme == Protocol.SS.value:
        return _parse_ss(uri, source_url)
    if scheme == Protocol.WIREGUARD.value:
        return _parse_wireguard(uri, source_url)
    if scheme == Protocol.MTPROTO.value:
        return _parse_mtproto(uri, source_url)
    protocol = Protocol(scheme)
    return _parse_trojan_like(uri, source_url, protocol)
