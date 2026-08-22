from __future__ import annotations

from typing import Any

from .models import Profile, Protocol


def _tls(profile: Profile) -> dict[str, Any]:
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": profile.params.get("sni", profile.server),
        "insecure": False,
    }
    if fingerprint := profile.params.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if profile.security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": profile.params["pbk"],
            "short_id": profile.params.get("sid", ""),
        }
    return tls


def _transport(profile: Profile) -> dict[str, Any] | None:
    kind = profile.transport.lower()
    if kind in {"tcp", "raw", "udp"}:
        return None
    if kind in {"ws", "websocket"}:
        transport: dict[str, Any] = {"type": "ws", "path": profile.params.get("path", "/")}
        if host := profile.params.get("host"):
            transport["headers"] = {"Host": host}
        return transport
    if kind == "grpc":
        return {"type": "grpc", "service_name": profile.params.get("servicename", "")}
    if kind == "h2":
        return {"type": "http", "host": [profile.params.get("host", profile.server)]}
    if kind == "httpupgrade":
        return {"type": "httpupgrade", "path": profile.params.get("path", "/")}
    if kind == "xhttp":
        return {"type": "http", "path": profile.params.get("path", "/")}
    return None


def _base_outbound(profile: Profile, tag: str) -> dict[str, Any]:
    return {
        "tag": tag,
        "server": profile.server,
        "server_port": profile.port,
    }


def _build_vless(profile: Profile, tag: str) -> dict[str, Any]:
    outbound = _base_outbound(profile, tag)
    outbound.update({"type": "vless", "uuid": profile.username, "tls": _tls(profile)})
    if flow := profile.params.get("flow"):
        outbound["flow"] = flow
    if transport := _transport(profile):
        outbound["transport"] = transport
    return outbound


def _build_trojan(profile: Profile, tag: str) -> dict[str, Any]:
    outbound = _base_outbound(profile, tag)
    outbound.update({"type": "trojan", "password": profile.secret, "tls": _tls(profile)})
    if transport := _transport(profile):
        outbound["transport"] = transport
    return outbound


def _build_hysteria2(profile: Profile, tag: str) -> dict[str, Any]:
    outbound = _base_outbound(profile, tag)
    outbound.update({"type": "hysteria2", "password": profile.secret, "tls": _tls(profile)})
    if obfs_password := profile.params.get("obfs-password") or profile.params.get("obfs"):
        outbound["obfs"] = {"type": "salamander", "password": obfs_password}
    return outbound


def build_singbox_config(profile: Profile, socks_port: int, tag: str) -> dict[str, object]:
    """Build a one-profile, loopback-only sing-box configuration for a temporary URL test."""
    builders = {
        Protocol.VLESS: _build_vless,
        Protocol.TROJAN: _build_trojan,
        Protocol.HYSTERIA2: _build_hysteria2,
    }
    outbound = builders[profile.protocol](profile, tag)
    return {
        "log": {"level": "error", "timestamp": True},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [outbound],
        "route": {"final": tag},
    }
