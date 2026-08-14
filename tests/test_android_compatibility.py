from __future__ import annotations

import importlib
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


def test_policy_rejects_explicit_tuic_version_other_than_five() -> None:
    """Catches acceptance of TUIC versions outside the approved v5 scope."""
    profile = parse_profile(
        TUIC_V5.replace("version=5", "version=4"), "https://source.example/list"
    )
    assert profile is not None
    assert evaluate_strict_secure(profile).reason == "unsupported_tuic_version"


@pytest.mark.parametrize(
    ("uri", "expected_type", "expected_security", "expected_transport"),
    [
        (VLESS_REALITY, "VL", "REALITY", "GRPC"),
        (TROJAN_TLS, "TR", "TLS", "TCP"),
        (HY2_TLS, "HY2", "TLS", "UDP"),
        (TUIC_V5, "TUIC", "TLS", "UDP"),
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


def test_singbox_config_exposes_one_profile_through_loopback_socks() -> None:
    """Catches a converter that cannot provide an isolated local path for one profile test."""
    module = importlib.import_module("subscription_collector.singbox_config")
    profile = parse_profile(TROJAN_TLS, "https://source.example/list")
    assert profile is not None
    config = module.build_singbox_config(profile, socks_port=41001, tag="profile")
    assert config["inbounds"] == [{"type": "socks", "listen": "127.0.0.1", "listen_port": 41001}]
    assert config["route"]["final"] == "profile"
    assert config["outbounds"][0]["type"] == "trojan"


def test_probe_quorum_requires_two_successful_urls_from_four() -> None:
    """Catches validation that publishes a profile after fewer than two successful probes."""
    module = importlib.import_module("subscription_collector.probe")
    passed = module.evaluate_probe_statuses(
        [204, 204, None, 503],
        expected_statuses=(204, 204, 204, 200),
        required_successes=2,
    )
    failed = module.evaluate_probe_statuses(
        [204, None, None, 200],
        expected_statuses=(204, 204, 204, 200),
        required_successes=3,
    )
    assert passed == 2
    assert failed == 2


def test_cli_emits_only_profiles_that_pass_active_probe_quorum(tmp_path) -> None:
    """Catches publishing a statically valid profile that fails the required URL-test quorum."""
    import asyncio
    import json

    import httpx

    from subscription_collector.cli import run_collection
    from subscription_collector.models import ProbeResult

    async def exercise() -> tuple[int, str, str]:
        input_path = tmp_path / "input.txt"
        output_path = tmp_path / "output.txt"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        rejected = TROJAN_TLS.replace("node.example.org", "reject.example.org")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=f"{TROJAN_TLS}\n{rejected}\n")

        async def fake_probe(profile):
            return ProbeResult(
                passed=profile.server == "node.example.org",
                successes=2 if profile.server == "node.example.org" else 1,
                median_latency_ms=42 if profile.server == "node.example.org" else None,
                error_category=None if profile.server == "node.example.org" else "timeout",
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            code = await run_collection(
                input_path=input_path,
                output_path=output_path,
                report_path=report_path,
                state_path=state_path,
                max_age_hours=72,
                strict_first_seen=False,
                fail_on_empty=False,
                client=client,
                verify_profiles=True,
                probe_runner=fake_probe,
            )
        return (
            code,
            output_path.read_text(encoding="utf-8"),
            report_path.read_text(encoding="utf-8"),
        )

    code, output, report = asyncio.run(exercise())
    parsed_report = json.loads(report)
    assert code == 0
    assert output.count("\n") == 1
    assert "TR-TLS-TCP-" in output
    assert parsed_report["counts"]["validation_passed"] == 1
    assert parsed_report["counts"]["validation_failed"] == 1
    assert parsed_report["validation"]["median_latency_ms"] == 42
    assert "trojan://" not in report
    assert "node.example.org" not in report
    assert "correct-horse" not in report


def test_probe_handles_process_disappearing_during_cleanup(monkeypatch, tmp_path) -> None:
    """Catches a ProcessLookupError that would abort collection after an individual failed probe."""
    import asyncio

    from subscription_collector import probe

    class GoneProcess:
        returncode = None

        def terminate(self) -> None:
            raise ProcessLookupError

        async def wait(self) -> int:
            return 0

    async def create_gone_process(*_args, **_kwargs):
        return GoneProcess()

    async def exercise():
        binary = tmp_path / "sing-box"
        binary.write_text("fixture", encoding="utf-8")
        monkeypatch.setattr(probe.asyncio, "create_subprocess_exec", create_gone_process)
        profile = parse_profile(TROJAN_TLS, "https://source.example/list")
        assert profile is not None
        return await probe.probe_profile(
            profile,
            binary,
            timeout_seconds=0.001,
            startup_timeout_seconds=0.001,
        )

    result = asyncio.run(exercise())
    assert result.passed is False
    assert result.error_category == "listener_timeout"
