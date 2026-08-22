from __future__ import annotations

import re

import pytest

from subscription_collector.dedup import deduplicate, profile_fingerprint
from subscription_collector.models import Protocol
from subscription_collector.parser import parse_profile
from subscription_collector.policy import evaluate_strict_secure
from subscription_collector.renamer import render_named_uri

REALITY_PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
VLESS_REALITY = (
    "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
    f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={REALITY_PBK}"
    "&type=grpc&serviceName=grpc#source-name"
)
TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)
HY2_TLS = "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com#source-name"
TUIC_V5 = (
    "tuic://123e4567-e89b-12d3-a456-426614174000:tuic-password@tuic.example.org:443"
    "?security=tls&sni=www.example.com&version=5#source-name"
)


@pytest.mark.parametrize(
    "uri",
    [
        "vmess://eyJ2IjoiMiJ9",
        "ss://aes-256-gcm:password@node.example.org:443",
        "wireguard://private-key@node.example.org:51820?publickey=peer&address=10.0.0.2/32",
        "naive://password@node.example.org:443?sni=www.example.com&security=tls",
    ],
)
def test_parser_rejects_protocols_outside_android_validation_scope(uri: str) -> None:
    """Catches accidental publication of profiles outside the four approved protocols."""
    assert parse_profile(uri, "https://source.example/list") is None


def test_hy2_alias_normalizes_to_hysteria2() -> None:
    """Catches loss of the standard hy2 URI alias required by Android clients."""
    profile = parse_profile(HY2_TLS, "https://source.example/list")
    assert profile is not None
    assert profile.protocol is Protocol.HYSTERIA2
    assert evaluate_strict_secure(profile).profile == profile


def test_parser_rejects_tuic_after_protocol_removal() -> None:
    """Catches accidental reintroduction of unsupported TUIC profiles."""
    assert parse_profile(TUIC_V5, "https://source.example/list") is None


@pytest.mark.parametrize(
    ("uri", "expected_type", "expected_security", "expected_transport"),
    [
        (VLESS_REALITY, "VL", "REALITY", "GRPC"),
        (TROJAN_TLS, "TR", "TLS", "TCP"),
        (HY2_TLS, "HY2", "TLS", "UDP"),
    ],
)
def test_renamer_emits_compact_ascii_android_fragment(
    uri: str,
    expected_type: str,
    expected_security: str,
    expected_transport: str,
) -> None:
    """Catches labels that require URI escaping or reveal endpoint and credential material."""
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    named = render_named_uri(profile, profile_fingerprint(profile))
    fragment = named.split("#", 1)[1]
    assert re.fullmatch(
        rf"{expected_type}-{expected_security}-{expected_transport}-[0-9A-Za-z]{{6}}",
        fragment,
    )
    assert "%" not in fragment
    assert "node.example" not in fragment
    assert "password" not in fragment
    assert "123e4567" not in fragment


def test_dedup_preserves_same_endpoint_when_sni_differs() -> None:
    """Catches endpoint matching that would collapse materially different TLS profiles."""
    first = parse_profile(
        "trojan://same-secret@node.example.org:443?security=tls&sni=a.example&fp=chrome#one",
        "https://source-a.example/list",
    )
    second = parse_profile(
        "trojan://same-secret@node.example.org:443?security=tls&sni=b.example&fp=chrome#two",
        "https://source-b.example/list",
    )
    assert first is not None and second is not None
    assert deduplicate([first, second]) == [first, second]


def test_dedup_removes_cosmetic_duplicate_with_reordered_query_and_remark() -> None:
    """Catches duplicate output caused solely by query ordering or an upstream display name."""
    first = parse_profile(
        "trojan://same-secret@node.example.org:443?security=tls&sni=a.example&fp=chrome#one",
        "https://source-a.example/list",
    )
    second = parse_profile(
        "trojan://same-secret@node.example.org:443?fp=chrome&sni=a.example&security=tls#two",
        "https://source-b.example/list",
    )
    assert first is not None and second is not None
    assert deduplicate([first, second]) == [first]


@pytest.mark.parametrize(
    ("first_uri", "second_uri"),
    [
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=a.example&fp=chrome&type=ws&path=%2Fgate",
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=a.example&fp=chrome&type=websocket&path=%2Fgate",
        ),
        (
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=a.example&fp=chrome&type=tcp",
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            "?encryption=none&security=tls&sni=a.example&fp=chrome&type=raw",
        ),
        (
            "trojan://correct-horse@node.example.org:443"
            "?security=tls&sni=a.example&fp=chrome&type=tcp&vendor-tag=promo",
            "trojan://correct-horse@node.example.org:443?security=tls&sni=a.example&fp=chrome",
        ),
        (
            "hy2://hy2-password@hy2.example.org:443?security=tls&sni=a.example#one",
            "hysteria2://hy2-password@hy2.example.org:443?sni=a.example&security=tls#two",
        ),
    ],
)
def test_dedup_matches_v2rayng_outbound_equivalence(first_uri: str, second_uri: str) -> None:
    """Mirror v2rayNG identity: transport aliases and vendor noise do not create new configs."""
    first = parse_profile(first_uri, "https://source-a.example/list")
    second = parse_profile(second_uri, "https://source-b.example/list")
    assert first is not None and second is not None
    assert profile_fingerprint(first) == profile_fingerprint(second)
    assert deduplicate([first, second]) == [first]


def test_dedup_keeps_distinct_stream_settings_as_separate_configurations() -> None:
    """Catches over-merging of profiles that clients treat as different connections."""
    ws_profile = parse_profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=a.example&fp=chrome&type=ws&path=%2Fgate",
        "https://source-a.example/list",
    )
    grpc_profile = parse_profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=a.example&fp=chrome&type=grpc&serviceName=svc",
        "https://source-b.example/list",
    )
    assert ws_profile is not None and grpc_profile is not None
    assert profile_fingerprint(ws_profile) != profile_fingerprint(grpc_profile)
    assert deduplicate([ws_profile, grpc_profile]) == [ws_profile, grpc_profile]
