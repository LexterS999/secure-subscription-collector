from __future__ import annotations

import pytest

from subscription_collector.analysis import analyze_profile
from subscription_collector.parser import parse_profile

PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _profile(uri: str):
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    return profile


@pytest.mark.parametrize(
    "uri",
    [
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=tcp",
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}"
        "&sid=0123abcd&type=tcp&flow=xtls-rprx-vision",
        "trojan://correct-horse@node.example.org:443"
        "?security=tls&sni=www.example.com&fp=firefox&type=ws&path=%2Fgateway",
        "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com&alpn=h3",
        "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com"
        "&obfs=salamander&obfs-password=secret&mport=20000-30000,40000",
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=edge"
        "&type=xhttp&path=%2Fapi&mode=stream-up",
    ],
)
def test_deep_analysis_accepts_client_compatible_profiles(uri: str) -> None:
    """Well-formed profiles of every protocol survive the deep analysis."""
    assert analyze_profile(_profile(uri)).profile is not None


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=unknownbrowser&type=tcp",
            "unknown_fingerprint",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
            "&alpn=h2,http%2F2&type=tcp",
            "invalid_alpn",
        ),
        (
            "trojan://correct-horse@node.example.org:443"
            "?security=tls&sni=www.example.com&fp=chrome&type=ws&path=gateway",
            "invalid_ws_path",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
            "&type=grpc&serviceName=svc&mode=super",
            "invalid_grpc_mode",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
            "&type=xhttp&mode=mega",
            "invalid_xhttp_mode",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}"
            "&sid=zzzz&type=tcp",
            "invalid_short_id",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}"
            "&spx=example.org&type=tcp",
            "invalid_spider_x",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            f"?encryption=none&security=reality&sni=192.0.2.1&fp=chrome&pbk={PBK}&type=tcp",
            "invalid_reality_sni",
        ),
        (
            "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com&obfs=http",
            "unsupported_obfs",
        ),
        (
            "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com"
            "&obfs=salamander",
            "missing_obfs_password",
        ),
        (
            "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com&mport=abc",
            "invalid_port_range",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
            "&type=tcp&flow=xtls-rprx-vision2",
            "unsupported_flow",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
            "&type=ws&flow=xtls-rprx-vision",
            "incompatible_flow",
        ),
    ],
)
def test_deep_analysis_rejects_profiles_clients_cannot_use(uri: str, reason: str) -> None:
    """Each defect maps to its specific redacted exclusion reason."""
    decision = analyze_profile(_profile(uri))
    assert decision.profile is None
    assert decision.reason == reason
