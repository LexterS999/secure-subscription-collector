from __future__ import annotations

import json
from collections.abc import Sequence

from .models import Profile, Protocol


def _required(value: str | None, field: str) -> str:
    if not value:
        raise ValueError(f"missing_{field}")
    return value


def _tls_settings(profile: Profile) -> dict[str, object]:
    settings: dict[str, object] = {
        "serverName": profile.params.get("sni", profile.server),
        "allowInsecure": False,
    }
    if fingerprint := profile.params.get("fp"):
        settings["fingerprint"] = fingerprint
    if alpn := profile.params.get("alpn"):
        settings["alpn"] = [value.strip() for value in alpn.split(",") if value.strip()]
    return settings


def _xhttp_extra(profile: Profile) -> dict[str, object] | None:
    value = profile.params.get("extra")
    if not value:
        return None
    try:
        extra = json.loads(value)
    except json.JSONDecodeError:
        return None
    return extra if isinstance(extra, dict) else None


def _transport_settings(profile: Profile) -> dict[str, object]:
    kind = profile.transport.lower()
    if kind == "raw":
        kind = "tcp"

    stream: dict[str, object] = {"network": kind}
    if profile.security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": profile.params.get("sni", profile.server),
            "fingerprint": _required(profile.params.get("fp"), "fingerprint"),
            "publicKey": _required(profile.params.get("pbk"), "reality_public_key"),
            "shortId": profile.params.get("sid", ""),
            "spiderX": profile.params.get("spx", ""),
        }
    else:
        stream["security"] = "tls"
        stream["tlsSettings"] = _tls_settings(profile)

    if kind == "ws":
        ws_settings: dict[str, object] = {"path": profile.params.get("path", "/")}
        if host := profile.params.get("host"):
            ws_settings["headers"] = {"Host": host}
        stream["wsSettings"] = ws_settings
    elif kind == "grpc":
        grpc_settings: dict[str, object] = {"serviceName": profile.params.get("servicename", "")}
        if authority := profile.params.get("authority"):
            grpc_settings["authority"] = authority
        if profile.params.get("mode") == "multi" or profile.params.get("multimode") == "true":
            grpc_settings["multiMode"] = True
        stream["grpcSettings"] = grpc_settings
    elif kind == "h2":
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {
            "host": profile.params.get("host", profile.server),
            "path": profile.params.get("path", "/"),
            "mode": "stream-one",
        }
    elif kind == "httpupgrade":
        http_upgrade_settings: dict[str, object] = {"path": profile.params.get("path", "/")}
        if host := profile.params.get("host"):
            http_upgrade_settings["host"] = host
        stream["httpupgradeSettings"] = http_upgrade_settings
    elif kind == "xhttp":
        xhttp_settings: dict[str, object] = {"path": profile.params.get("path", "/")}
        if host := profile.params.get("host"):
            xhttp_settings["host"] = host
        if mode := profile.params.get("mode"):
            xhttp_settings["mode"] = mode
        if extra := _xhttp_extra(profile):
            xhttp_settings["extra"] = extra
        stream["xhttpSettings"] = xhttp_settings
    return stream


def _vless_outbound(profile: Profile, tag: str) -> dict[str, object]:
    user: dict[str, object] = {
        "id": _required(profile.username, "uuid"),
        "encryption": profile.params.get("encryption", "none"),
    }
    if flow := profile.params.get("flow"):
        user["flow"] = flow
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": profile.server,
                    "port": profile.port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": _transport_settings(profile),
    }


def _trojan_outbound(profile: Profile, tag: str) -> dict[str, object]:
    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": profile.server,
                    "port": profile.port,
                    "password": _required(profile.secret, "password"),
                }
            ]
        },
        "streamSettings": _transport_settings(profile),
    }


def _hysteria2_outbound(profile: Profile, tag: str) -> dict[str, object]:
    stream: dict[str, object] = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": _tls_settings(profile),
        "hysteriaSettings": {"version": 2, "auth": _required(profile.secret, "password")},
    }
    if profile.params.get("obfs", "").lower() == "salamander":
        stream["finalmask"] = {
            "udp": [
                {
                    "type": "salamander",
                    "settings": {
                        "password": _required(profile.params.get("obfs-password"), "obfs_password")
                    },
                }
            ]
        }
    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": profile.server,
            "port": profile.port,
        },
        "streamSettings": stream,
    }


def build_xray_batch_config(
    profiles: Sequence[Profile], socks_ports: Sequence[int]
) -> dict[str, object]:
    """Build a loopback-only Xray batch that routes every SOCKS port to one outbound."""
    if not profiles or len(profiles) != len(socks_ports):
        raise ValueError("profiles_and_ports_must_match")
    if len(set(socks_ports)) != len(socks_ports) or any(
        not 1 <= port <= 65535 for port in socks_ports
    ):
        raise ValueError("invalid_or_duplicate_socks_port")

    builders = {
        Protocol.VLESS: _vless_outbound,
        Protocol.TROJAN: _trojan_outbound,
        Protocol.HYSTERIA2: _hysteria2_outbound,
    }
    inbounds: list[dict[str, object]] = []
    outbounds: list[dict[str, object]] = []
    rules: list[dict[str, object]] = []
    for index, (profile, port) in enumerate(zip(profiles, socks_ports, strict=True)):
        outbound_tag = f"profile-{index}"
        inbound_tag = f"probe-inbound-{index}"
        try:
            outbound = builders[profile.protocol](profile, outbound_tag)
        except KeyError as exc:
            raise ValueError("unsupported_protocol") from exc
        inbounds.append(
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "tag": inbound_tag,
            }
        )
        outbounds.append(outbound)
        rules.append({"type": "field", "localPort": port, "outboundTag": outbound_tag})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }


def build_xray_config(profile: Profile, socks_port: int, tag: str) -> dict[str, object]:
    """Build a one-profile Xray configuration with a loopback-only SOCKS listener."""
    if not 1 <= socks_port <= 65535:
        raise ValueError("socks_port must be between 1 and 65535")
    builders = {
        Protocol.VLESS: _vless_outbound,
        Protocol.TROJAN: _trojan_outbound,
        Protocol.HYSTERIA2: _hysteria2_outbound,
    }
    try:
        outbound = builders[profile.protocol](profile, tag)
    except KeyError as exc:
        raise ValueError("unsupported_protocol") from exc
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "tag": "probe-inbound",
            }
        ],
        "outbounds": [outbound],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["probe-inbound"],
                    "outboundTag": tag,
                }
            ]
        },
    }
