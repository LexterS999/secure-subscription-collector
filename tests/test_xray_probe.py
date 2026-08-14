from __future__ import annotations

from pathlib import Path

import pytest

from subscription_collector.probe import is_public_ip_response


@pytest.mark.parametrize(
    "body",
    [
        "",
        "not-an-ip",
        "10.0.0.7",
        "127.0.0.1",
        "192.168.1.20",
        "169.254.10.2",
        "::1",
        "fc00::1",
    ],
)
def test_is_public_ip_response_rejects_invalid_or_non_global_addresses(body: str) -> None:
    """Catches accepting a failed, private, loopback, or malformed IP-echo response."""
    assert is_public_ip_response(body) is False


def test_is_public_ip_response_accepts_global_ip_literal() -> None:
    """Catches discarding a valid public IP-echo response because of surrounding whitespace."""
    assert is_public_ip_response(" 1.1.1.1\n") is True


def test_probe_profile_closes_xray_listener_after_failed_request(tmp_path, monkeypatch) -> None:
    """Catches an Xray child process or loopback listener left alive after a failed probe."""
    import asyncio
    import os
    import socket

    from subscription_collector import probe
    from subscription_collector.parser import parse_profile

    xray_path = os.environ.get("XRAY_TEST_BINARY")
    if not xray_path:
        pytest.skip("XRAY_TEST_BINARY is not set")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    monkeypatch.setattr(probe, "_reserve_loopback_port", lambda: port)
    profile = parse_profile(
        "trojan://correct-horse@127.0.0.1:1"
        "?security=tls&sni=www.example.com&fp=chrome&type=tcp",
        "https://source.example/list",
    )
    assert profile is not None

    result = asyncio.run(
        probe.probe_profile(
            profile,
            Path(xray_path),
            ip_echo_url="http://127.0.0.1:1",
            timeout_seconds=1,
            startup_timeout_seconds=2,
        )
    )

    assert result.passed is False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as verifier:
        verifier.settimeout(0.2)
        assert verifier.connect_ex(("127.0.0.1", port)) != 0
