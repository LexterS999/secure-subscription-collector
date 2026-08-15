from __future__ import annotations

from dataclasses import replace
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


def test_probe_profile_closes_xray_listener_after_failed_request(
    tmp_path, monkeypatch, config_for
) -> None:
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
        "trojan://correct-horse@127.0.0.1:1?security=tls&sni=www.example.com&fp=chrome&type=tcp",
        "https://source.example/list",
    )
    assert profile is not None

    settings = replace(
        config_for().ip_validation,
        ip_echo_urls=("https://127.0.0.1:1",),
        http_check_urls=("https://127.0.0.1:1",),
        timeout_seconds=1,
        startup_timeout_seconds=2,
    )
    result = asyncio.run(probe.probe_profile(profile, Path(xray_path), settings=settings))

    assert result.passed is False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as verifier:
        verifier.settimeout(0.2)
        assert verifier.connect_ex(("127.0.0.1", port)) != 0


def test_probe_profile_returns_fail_closed_result_when_xray_exits_before_listener(
    tmp_path, config_for
) -> None:
    """Catches an early Xray exit escaping from a single failed profile into the workflow."""
    import asyncio

    from subscription_collector.parser import parse_profile
    from subscription_collector.probe import probe_profile

    profile = parse_profile(
        "trojan://correct-horse@node.example.org:443"
        "?security=tls&sni=www.example.com&fp=chrome&type=tcp",
        "https://source.example/list",
    )
    assert profile is not None
    failing_xray = tmp_path / "xray"
    failing_xray.write_text(
        '#!/bin/sh\nif [ "$2" = "-test" ]; then exit 0; fi\nsleep 0.01\nexit 23\n',
        encoding="utf-8",
    )
    failing_xray.chmod(0o755)

    settings = replace(config_for().ip_validation, timeout_seconds=0.1, startup_timeout_seconds=0.2)
    result = asyncio.run(probe_profile(profile, failing_xray, settings=settings))

    assert result.passed is False
    assert result.error_category == "process_exited"


def test_probe_batch_returns_fail_closed_results_when_xray_exits_before_listeners(
    tmp_path, config_for
) -> None:
    """Catches a failed batch process cancelling the complete collection task."""
    import asyncio

    from subscription_collector.parser import parse_profile
    from subscription_collector.probe import probe_batch

    profiles = [
        parse_profile(
            "trojan://correct-horse@node-one.example.org:443"
            "?security=tls&sni=www.example.com&fp=chrome&type=tcp",
            "https://source.example/list",
        ),
        parse_profile(
            "trojan://correct-horse@node-two.example.org:443"
            "?security=tls&sni=www.example.com&fp=chrome&type=tcp",
            "https://source.example/list",
        ),
    ]
    assert all(profile is not None for profile in profiles)
    failing_xray = tmp_path / "xray"
    failing_xray.write_text(
        '#!/bin/sh\nif [ "$2" = "-test" ]; then exit 0; fi\nsleep 0.01\nexit 23\n',
        encoding="utf-8",
    )
    failing_xray.chmod(0o755)

    settings = replace(
        config_for().ip_validation,
        timeout_seconds=0.1,
        startup_timeout_seconds=0.2,
        request_concurrency=2,
    )
    results = asyncio.run(
        probe_batch(
            [profile for profile in profiles if profile is not None],
            failing_xray,
            settings=settings,
        )
    )

    assert [result.passed for result in results] == [False, False]
    assert [result.error_category for result in results] == [
        "process_exited",
        "process_exited",
    ]


def test_probe_uses_dedicated_timeout_for_xray_config_validation(tmp_path, config_for) -> None:
    """Catches reusing listener startup timeout for a slower Xray JSON validation command."""
    import asyncio

    from subscription_collector.parser import parse_profile
    from subscription_collector.probe import probe_profile

    profile = parse_profile(
        "trojan://correct-horse@node.example.org:443"
        "?security=tls&sni=www.example.com&fp=chrome&type=tcp",
        "https://source.example/list",
    )
    assert profile is not None
    delayed_test_xray = tmp_path / "xray"
    delayed_test_xray.write_text(
        '#!/bin/sh\nif [ "$2" = "-test" ]; then sleep 0.05; exit 0; fi\nexit 23\n',
        encoding="utf-8",
    )
    delayed_test_xray.chmod(0o755)

    settings = replace(
        config_for().ip_validation,
        config_test_timeout_seconds=0.2,
        startup_timeout_seconds=0.01,
    )
    result = asyncio.run(probe_profile(profile, delayed_test_xray, settings=settings))

    assert result.passed is False
    assert result.error_category in {"process_exited", "listener_timeout"}
    assert result.error_category != "config_invalid"
