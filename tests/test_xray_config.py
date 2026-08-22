from __future__ import annotations

import pytest

from subscription_collector.parser import parse_profile
from subscription_collector.xray_config import build_xray_config

PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _profile(uri: str):
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    return profile


def test_build_xray_config_creates_loopback_socks_and_vless_reality() -> None:
    """Catches proxy listener exposure or malformed VLESS Reality credentials."""
    profile = _profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}"
        "&sid=abcd&type=grpc&serviceName=grpc-service"
    )

    config = build_xray_config(profile, 19200, "profile")

    assert config["inbounds"] == [
        {
            "listen": "127.0.0.1",
            "port": 19200,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "tag": "probe-inbound",
        }
    ]
    outbound = config["outbounds"][0]
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"] == [
        {
            "address": "node.example.org",
            "port": 443,
            "users": [
                {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "encryption": "none",
                }
            ],
        }
    ]
    assert outbound["streamSettings"] == {
        "network": "grpc",
        "security": "reality",
        "realitySettings": {
            "serverName": "www.example.com",
            "fingerprint": "chrome",
            "publicKey": PBK,
            "shortId": "abcd",
            "spiderX": "",
        },
        "grpcSettings": {"serviceName": "grpc-service"},
    }
    assert config["routing"] == {
        "rules": [
            {
                "type": "field",
                "inboundTag": ["probe-inbound"],
                "outboundTag": "profile",
            }
        ]
    }


def test_build_xray_config_populates_trojan_tls_websocket() -> None:
    """Catches loss of Trojan password, TLS SNI, or WebSocket request metadata."""
    profile = _profile(
        "trojan://correct-horse@trojan.example.org:443"
        "?security=tls&sni=www.example.com&fp=firefox&type=ws&path=%2Fgateway&host=cdn.example.com"
    )

    config = build_xray_config(profile, 19201, "profile")

    outbound = config["outbounds"][0]
    assert outbound["protocol"] == "trojan"
    assert outbound["settings"] == {
        "servers": [
            {
                "address": "trojan.example.org",
                "port": 443,
                "password": "correct-horse",
            }
        ]
    }
    assert outbound["streamSettings"] == {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
            "serverName": "www.example.com",
            "fingerprint": "firefox",
            "allowInsecure": False,
        },
        "wsSettings": {
            "path": "/gateway",
            "headers": {"Host": "cdn.example.com"},
        },
    }


def test_build_xray_config_populates_hysteria2_auth_and_obfuscation() -> None:
    """Catches invalid Hysteria2 auth, QUIC transport, or Salamander mapping."""
    profile = _profile(
        "hy2://hy2-password@hy2.example.org:8443"
        "?security=tls&sni=www.example.com&obfs=salamander&obfs-password=obfs-secret"
    )

    config = build_xray_config(profile, 19202, "profile")

    outbound = config["outbounds"][0]
    assert outbound["protocol"] == "hysteria"
    assert outbound["settings"] == {
        "version": 2,
        "address": "hy2.example.org",
        "port": 8443,
    }
    assert outbound["streamSettings"] == {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": {
            "serverName": "www.example.com",
            "allowInsecure": False,
        },
        "hysteriaSettings": {"version": 2, "auth": "hy2-password"},
        "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}]},
    }


def test_generated_config_passes_official_xray_syntax_validation(tmp_path, monkeypatch) -> None:
    """Catches a JSON shape that matches unit assertions but is rejected by Xray itself."""
    import json
    import os
    import subprocess

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profile = _profile(
        "trojan://correct-horse@trojan.example.org:443"
        "?security=tls&sni=www.example.com&fp=firefox&type=ws&path=%2Fgateway&host=cdn.example.com"
    )
    config_path = tmp_path / "profile.json"
    config_path.write_text(
        json.dumps(build_xray_config(profile, 19203, "profile")), encoding="utf-8"
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "uri",
    [
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}"
        "&sid=abcd&type=grpc&serviceName=grpc-service",
        "hy2://hy2-password@hy2.example.org:8443"
        "?security=tls&sni=www.example.com&obfs=salamander&obfs-password=obfs-secret",
    ],
)
def test_all_remaining_protocol_configs_pass_official_xray_syntax_validation(
    tmp_path, uri: str
) -> None:
    """Catches a VLESS or Hysteria2 mapping that is syntactically invalid to Xray."""
    import json
    import os
    import subprocess

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profile = _profile(uri)
    config_path = tmp_path / "profile.json"
    config_path.write_text(
        json.dumps(build_xray_config(profile, 19204, "profile")), encoding="utf-8"
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "transport_query",
    [
        "type=tcp",
        "type=raw",
        "type=ws&path=%2Fsocket&host=cdn.example.com",
        "type=grpc&serviceName=grpc-service",
        "type=h2&path=%2Fconnect&host=cdn.example.com",
        "type=httpupgrade&path=%2Fupgrade&host=cdn.example.com",
        "type=xhttp&path=%2Fxhttp",
    ],
)
def test_vless_allowed_transports_pass_official_xray_syntax_validation(
    tmp_path, transport_query: str
) -> None:
    """Catches a static-policy transport that cannot be represented in Xray JSON."""
    import json
    import os
    import subprocess

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profile = _profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        f"?encryption=none&security=tls&sni=www.example.com&fp=chrome&{transport_query}"
    )
    config_path = tmp_path / "profile.json"
    config_path.write_text(
        json.dumps(build_xray_config(profile, 19205, "profile")), encoding="utf-8"
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_batch_config_routes_each_loopback_port_to_its_own_outbound() -> None:
    """Catches batch routing that can send an IP check through another profile's outbound."""
    from subscription_collector.xray_config import build_xray_batch_config

    profiles = [
        _profile(
            "trojan://correct-horse@trojan.example.org:443"
            "?security=tls&sni=www.example.com&fp=firefox&type=tcp"
        ),
        _profile(
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
            f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={PBK}&type=grpc"
        ),
    ]

    config = build_xray_batch_config(profiles, [31001, 31002])

    assert [inbound["port"] for inbound in config["inbounds"]] == [31001, 31002]
    assert [inbound["tag"] for inbound in config["inbounds"]] == [
        "probe-inbound-0",
        "probe-inbound-1",
    ]
    assert [outbound["tag"] for outbound in config["outbounds"]] == [
        "profile-0",
        "profile-1",
    ]
    assert config["routing"]["rules"] == [
        {"type": "field", "localPort": 31001, "outboundTag": "profile-0"},
        {"type": "field", "localPort": 31002, "outboundTag": "profile-1"},
    ]


def test_batch_config_passes_official_xray_syntax_validation(tmp_path) -> None:
    """Catches batch localPort routing rejected by Xray even when Python accepts it."""
    import json
    import os
    import subprocess

    from subscription_collector.xray_config import build_xray_batch_config

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profiles = [
        _profile(
            "trojan://correct-horse@trojan.example.org:443"
            "?security=tls&sni=www.example.com&fp=firefox&type=tcp"
        ),
        _profile(
            "hy2://hy2-password@hy2.example.org:8443"
            "?security=tls&sni=www.example.com&obfs=salamander&obfs-password=obfs-secret"
        ),
    ]
    config_path = tmp_path / "batch.json"
    config_path.write_text(
        json.dumps(build_xray_batch_config(profiles, [31101, 31102])), encoding="utf-8"
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_large_batch_config_passes_official_xray_syntax_validation(tmp_path) -> None:
    """Catches a batch-size increase that creates a JSON Xray cannot parse."""
    import json
    import os
    import subprocess

    from subscription_collector.xray_config import build_xray_batch_config

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profile = _profile(
        "trojan://correct-horse@trojan.example.org:443"
        "?security=tls&sni=www.example.com&fp=firefox&type=tcp"
    )
    config_path = tmp_path / "large-batch.json"
    config_path.write_text(
        json.dumps(build_xray_batch_config([profile] * 512, range(32000, 32512))),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_build_xray_config_preserves_tls_and_grpc_compatibility_parameters() -> None:
    """Catches loss of URI parameters required by TLS and gRPC proxy endpoints."""
    profile = _profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
        "&alpn=h2,http%2F1.1&type=grpc&serviceName=grpc-service"
        "&authority=grpc.example.com&mode=multi"
    )

    config = build_xray_config(profile, 19206, "profile")

    stream = config["outbounds"][0]["streamSettings"]
    assert stream["tlsSettings"]["alpn"] == ["h2", "http/1.1"]
    assert stream["grpcSettings"] == {
        "serviceName": "grpc-service",
        "authority": "grpc.example.com",
        "multiMode": True,
    }


def test_build_xray_config_preserves_xhttp_compatibility_parameters() -> None:
    """Catches loss of XHTTP endpoint settings required by modern VLESS share links."""
    profile = _profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=xhttp"
        "&host=cdn.example.com&path=%2Fapi&mode=stream-up"
        "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"
    )

    config = build_xray_config(profile, 19207, "profile")

    assert config["outbounds"][0]["streamSettings"]["xhttpSettings"] == {
        "host": "cdn.example.com",
        "path": "/api",
        "mode": "stream-up",
        "extra": {"xPaddingBytes": "100-1000"},
    }


def test_extended_xhttp_config_passes_official_xray_syntax_validation(tmp_path) -> None:
    """Catches compatibility fields accepted by unit tests but rejected by the Xray binary."""
    import json
    import os
    import subprocess

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    profile = _profile(
        "vless://123e4567-e89b-12d3-a456-426614174000@node.example.org:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=xhttp"
        "&host=cdn.example.com&path=%2Fapi&mode=stream-up"
        "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"
    )
    config_path = tmp_path / "extended-xhttp.json"
    config_path.write_text(
        json.dumps(build_xray_config(profile, 19208, "profile")), encoding="utf-8"
    )
    config_path.chmod(0o600)

    completed = subprocess.run(
        [xray_path, "run", "-test", "-c", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
