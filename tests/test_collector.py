from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from subscription_collector.cli import run_collection
from subscription_collector.decoder import extract_candidate_lines
from subscription_collector.dedup import deduplicate, profile_fingerprint
from subscription_collector.fetcher import fetch_sources
from subscription_collector.input_reader import InputError, read_input_urls
from subscription_collector.models import Freshness, Profile, Protocol
from subscription_collector.parser import parse_profile
from subscription_collector.policy import evaluate_strict_secure
from subscription_collector.renamer import render_named_uri
from subscription_collector.state import update_state
from subscription_collector.writer import write_text_atomic

REALITY_PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
VLESS_SECURE = (
    "vless://123e4567-e89b-12d3-a456-426614174000@edge.example.org:443"
    f"?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk={REALITY_PBK}"
    "&type=grpc&serviceName=grpc#untrusted-source-name"
)
TROJAN_SECURE = (
    "trojan://a-strong-password@edge.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome#untrusted-source-name"
)


def test_profile_rejects_port_outside_network_range() -> None:
    """Catches removal of network-port validation in the core data contract."""
    with pytest.raises(ValueError, match="port"):
        Profile(
            protocol=Protocol.VLESS,
            server="edge.example.org",
            port=0,
            username="123e4567-e89b-12d3-a456-426614174000",
            secret=None,
            security="reality",
            transport="grpc",
            params={},
            source_url="https://source.example/list",
            original_uri=VLESS_SECURE,
        )


def test_input_reader_accepts_only_distinct_https_urls_and_comments(tmp_path: Path) -> None:
    """Catches accidental acceptance of repeated or non-HTTPS subscription URLs."""
    source_file = tmp_path / "input.txt"
    source_file.write_text(
        "# comment\nhttps://a.example/sub\nhttps://a.example/sub\nhttps://b.example/list # label\n",
        encoding="utf-8",
    )
    assert read_input_urls(source_file) == ["https://a.example/sub", "https://b.example/list"]


@pytest.mark.parametrize("line", ["http://a.example/list", "not-a-url", "https:///missing-host"])
def test_input_reader_rejects_non_https_or_malformed_urls(tmp_path: Path, line: str) -> None:
    """Catches bypasses of the source transport constraint."""
    source_file = tmp_path / "input.txt"
    source_file.write_text(f"{line}\n", encoding="utf-8")
    with pytest.raises(InputError):
        read_input_urls(source_file)


def test_decoder_extracts_base64_subscription_once() -> None:
    """Catches loss of standard base64 subscription support."""
    payload = base64.b64encode(f"{VLESS_SECURE}\n{TROJAN_SECURE}\n".encode()).decode()
    assert extract_candidate_lines(payload) == [VLESS_SECURE, TROJAN_SECURE]


def test_decoder_ignores_non_uri_garbage() -> None:
    """Catches an overly permissive decoder that invents candidates from prose."""
    assert extract_candidate_lines("hello world\nnot a subscription\n") == []


def test_fetcher_excludes_source_with_last_modified_older_than_72_hours() -> None:
    """Catches an off-by-one or missing source-freshness filter."""

    async def exercise() -> None:
        old = datetime.now(UTC) - timedelta(hours=72, seconds=1)

        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == "https://source.example/list"
            return httpx.Response(
                200,
                headers={"Last-Modified": old.strftime("%a, %d %b %Y %H:%M:%S GMT")},
                text=VLESS_SECURE,
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await fetch_sources(["https://source.example/list"], client, datetime.now(UTC))
        assert result[0].freshness is Freshness.STALE
        assert result[0].text is None

    asyncio.run(exercise())


def test_fetcher_admits_source_without_last_modified_as_unknown() -> None:
    """Catches an incorrect rule that rejects sources whose age cannot be proven."""

    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=VLESS_SECURE)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await fetch_sources(["https://source.example/list"], client, datetime.now(UTC))
        assert result[0].freshness is Freshness.UNKNOWN
        assert result[0].text == VLESS_SECURE

    asyncio.run(exercise())


def test_parser_normalizes_alias_and_discards_display_fragment() -> None:
    """Catches failure to normalise security-relevant VLESS fields."""
    profile = parse_profile(VLESS_SECURE, "https://source.example/list")
    assert profile is not None
    assert profile.protocol is Protocol.VLESS
    assert profile.security == "reality"
    assert profile.transport == "grpc"
    assert profile.params["pbk"] == REALITY_PBK
    assert "untrusted-source-name" not in profile.original_uri.split("#", 1)[0]


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (VLESS_SECURE, Protocol.VLESS),
        (TROJAN_SECURE, Protocol.TROJAN),
        (
            "ss://aes-256-gcm:correct-horse-battery-staple@ss.example.org:8443#old",
            Protocol.SS,
        ),
        (
            "hysteria2://hy2-password@hy2.example.org:443?sni=www.example.com&security=tls#old",
            Protocol.HYSTERIA2,
        ),
        (
            "tuic://123e4567-e89b-12d3-a456-426614174000:tuic-password@tuic.example.org:443?sni=www.example.com&security=tls#old",
            Protocol.TUIC,
        ),
        (
            "wireguard://private-key@wg.example.org:51820?publickey=peer-public-key&address=10.0.0.2/32#old",
            Protocol.WIREGUARD,
        ),
        (
            "naive://naive-password@naive.example.org:443?sni=www.example.com&security=tls#old",
            Protocol.NAIVE,
        ),
        (
            "anytls://anytls-password@anytls.example.org:443?sni=www.example.com&security=tls#old",
            Protocol.ANYTLS,
        ),
        (
            "juicity://123e4567-e89b-12d3-a456-426614174000:juicity-password@juicity.example.org:443?sni=www.example.com&security=tls#old",
            Protocol.JUICITY,
        ),
        (
            "tg://proxy?server=mt.example.org&port=443&secret=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee#old",
            Protocol.MTPROTO,
        ),
    ],
)
def test_parser_supports_each_allowed_protocol(uri: str, expected: Protocol) -> None:
    """Catches accidental removal of any declared supported protocol parser."""
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    assert profile.protocol is expected


@pytest.mark.parametrize(
    "uri", ["socks5://a.example:1080", "http://a.example:8080", "ssr://payload", "bogus://x"]
)
def test_parser_excludes_unsupported_protocols(uri: str) -> None:
    """Catches acceptance of profiles outside the audited strict policy."""
    assert parse_profile(uri, "https://source.example/list") is None


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        (VLESS_SECURE.replace("fp=chrome", "fp=chrome&allowInsecure=1"), "insecure_flag"),
        (VLESS_SECURE.replace("&sni=www.example.com", ""), "missing_sni"),
        (VLESS_SECURE.replace("&fp=chrome", ""), "missing_fingerprint"),
        (VLESS_SECURE.replace("security=reality", "security=none"), "missing_security"),
        ("ss://table:password@ss.example.org:443#old", "legacy_cipher"),
        (
            "tg://proxy?server=mt.example.org&port=443&secret=not-hex#old",
            "invalid_mtproto_secret",
        ),
    ],
)
def test_strict_policy_rejects_each_insecure_profile(uri: str, reason: str) -> None:
    """Catches a missing branch in the strict static security policy."""
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    decision = evaluate_strict_secure(profile)
    assert decision.profile is None
    assert decision.reason == reason


@pytest.mark.parametrize(
    "uri",
    [
        VLESS_SECURE,
        TROJAN_SECURE,
        "ss://aes-256-gcm:correct-horse-battery-staple@ss.example.org:8443#old",
        "hysteria2://hy2-password@hy2.example.org:443?sni=www.example.com&security=tls#old",
        "tuic://123e4567-e89b-12d3-a456-426614174000:tuic-password@tuic.example.org:443?sni=www.example.com&security=tls#old",
        "wireguard://private-key@wg.example.org:51820?publickey=peer-public-key&address=10.0.0.2/32#old",
        "naive://naive-password@naive.example.org:443?sni=www.example.com&security=tls#old",
        "anytls://anytls-password@anytls.example.org:443?sni=www.example.com&security=tls#old",
        "juicity://123e4567-e89b-12d3-a456-426614174000:juicity-password@juicity.example.org:443?sni=www.example.com&security=tls#old",
        "tg://proxy?server=mt.example.org&port=443&secret=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee#old",
    ],
)
def test_strict_policy_admits_complete_secure_profiles(uri: str) -> None:
    """Catches an over-strict policy that drops a complete supported profile."""
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    decision = evaluate_strict_secure(profile)
    assert decision.profile == profile
    assert decision.reason is None


def test_deduplication_ignores_query_order_and_old_name() -> None:
    """Catches duplicate output caused by cosmetic URI differences."""
    first = parse_profile(TROJAN_SECURE, "https://a.example/list")
    second = parse_profile(
        "trojan://a-strong-password@edge.example.org:443?fp=chrome&sni=www.example.com&security=tls#other",
        "https://b.example/list",
    )
    assert first is not None and second is not None
    assert deduplicate([first, second]) == [first]
    assert profile_fingerprint(first) == profile_fingerprint(second)


def test_renamer_replaces_untrusted_name_without_secret_leakage() -> None:
    """Catches output labels that expose credentials or preserve source-controlled names."""
    profile = parse_profile(VLESS_SECURE, "https://source.example/list")
    assert profile is not None
    named = render_named_uri(profile, profile_fingerprint(profile))
    assert "VLESS%20%E2%80%A2%20REALITY%20%E2%80%A2%20GRPC" in named
    assert "untrusted-source-name" not in named
    assert "123e4567-e89b-12d3-a456-426614174000" not in named.split("#", 1)[1]
    assert REALITY_PBK not in named.split("#", 1)[1]


def test_state_records_only_fingerprint_and_seen_times(tmp_path: Path) -> None:
    """Catches persistence of raw URI secrets or failure to retain first-seen time."""
    state_path = tmp_path / "state.json"
    fingerprint = "a" * 64
    now = datetime(2026, 8, 14, 12, tzinfo=UTC)
    state = update_state(state_path, [fingerprint], now)
    assert state[fingerprint].first_seen_at == "2026-08-14T12:00:00Z"
    assert (
        json.loads(state_path.read_text(encoding="utf-8"))[fingerprint]["last_seen_at"]
        == "2026-08-14T12:00:00Z"
    )
    assert VLESS_SECURE not in state_path.read_text(encoding="utf-8")


def test_atomic_writer_replaces_prior_file_contents(tmp_path: Path) -> None:
    """Catches partial append semantics instead of required complete replacement."""
    output = tmp_path / "output.txt"
    output.write_text("old\n", encoding="utf-8")
    write_text_atomic(output, "new\n")
    assert output.read_text(encoding="utf-8") == "new\n"


def test_cli_collects_only_from_source_url_and_rewrites_output(tmp_path: Path) -> None:
    """Catches profile-endpoint probing or failure to create the unified output/report/state."""

    async def exercise() -> int:
        input_path = tmp_path / "input.txt"
        output_path = tmp_path / "output.txt"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            return httpx.Response(200, text=f"{VLESS_SECURE}\n{TROJAN_SECURE}\n")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_collection(
                input_path=input_path,
                output_path=output_path,
                report_path=report_path,
                state_path=state_path,
                max_age_hours=72,
                strict_first_seen=False,
                fail_on_empty=False,
                client=client,
            )

    assert asyncio.run(exercise()) == 0
    assert (tmp_path / "output.txt").read_text(encoding="utf-8").count("\n") == 2
    report_text = (tmp_path / "report.json").read_text(encoding="utf-8")
    assert REALITY_PBK not in report_text
    assert "a-strong-password" not in report_text


def test_cli_fails_on_empty_only_when_requested(tmp_path: Path) -> None:
    """Catches incorrect exit handling for empty strict-filtered results."""

    async def exercise() -> tuple[int, int]:
        input_path = tmp_path / "input.txt"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="socks5://not-allowed.example:1080\n")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            regular = await run_collection(
                input_path=input_path,
                output_path=tmp_path / "regular.txt",
                report_path=tmp_path / "regular.json",
                state_path=tmp_path / "regular-state.json",
                max_age_hours=72,
                strict_first_seen=False,
                fail_on_empty=False,
                client=client,
            )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            strict = await run_collection(
                input_path=input_path,
                output_path=tmp_path / "strict.txt",
                report_path=tmp_path / "strict.json",
                state_path=tmp_path / "strict-state.json",
                max_age_hours=72,
                strict_first_seen=False,
                fail_on_empty=True,
                client=client,
            )
        return regular, strict

    assert asyncio.run(exercise()) == (0, 2)


def test_update_workflow_allows_only_schedule_and_manual_dispatch() -> None:
    """Catches a data-update workflow that would run after an arbitrary code change."""
    workflow = Path(".github/workflows/update-output.yml").read_text(encoding="utf-8")
    assert "'on':" in workflow
    assert "cron: '0 */4 * * *'" in workflow
    assert "workflow_dispatch: {}" in workflow
    assert "push:" not in workflow
    assert "pull_request:" not in workflow


def test_state_retains_prior_first_seen_records_within_freshness_window(tmp_path: Path) -> None:
    """Catches loss of first-seen history when a profile is absent in one collection run."""
    state_path = tmp_path / "state.json"
    first = "a" * 64
    second = "b" * 64
    first_run = datetime(2026, 8, 14, 12, tzinfo=UTC)
    update_state(state_path, [first], first_run)
    state = update_state(state_path, [second], first_run + timedelta(hours=1))
    assert state[first].first_seen_at == "2026-08-14T12:00:00Z"
    assert state[second].first_seen_at == "2026-08-14T13:00:00Z"


def test_fetcher_rejects_redirect_from_https_to_http() -> None:
    """Catches a redirect that would downgrade the trusted source transport to HTTP."""

    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            if request.url.host == "source.example":
                return httpx.Response(302, headers={"Location": "http://downgrade.example/list"})
            return httpx.Response(200, text=VLESS_SECURE)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, datetime.now(UTC)
            )
        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == "redirect_non_https"
        assert requests == ["https://source.example/list"]

    asyncio.run(exercise())


def test_parser_returns_none_for_malformed_ipv6_uri() -> None:
    """Catches malformed input that would otherwise raise and abort a whole source batch."""
    malformed = (
        "vless://123e4567-e89b-12d3-a456-426614174000@[broken:443"
        "?encryption=none&security=tls&sni=www.example.com&fp=chrome"
    )
    assert parse_profile(malformed, "https://source.example/list") is None


def test_parser_accepts_sip002_base64_shadowsocks_credentials() -> None:
    """Catches loss of valid Shadowsocks links that encode method and password in base64."""
    encoded = (
        base64.urlsafe_b64encode(b"aes-256-gcm:correct-horse-battery-staple").decode().rstrip("=")
    )
    uri = f"ss://{encoded}@ss.example.org:8443#old"
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    assert profile.protocol is Protocol.SS
    assert profile.params["method"] == "aes-256-gcm"
    assert profile.secret == "correct-horse-battery-staple"
    assert evaluate_strict_secure(profile).profile == profile


def test_fetcher_rejects_redirect_with_credentials() -> None:
    """Catches a redirect that would introduce source URL credentials outside input.txt controls."""

    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(
                302,
                headers={"Location": "https://user:pass@redirect.example/list"},
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, datetime.now(UTC)
            )
        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == "redirect_credentials"
        assert requests == ["https://source.example/list"]

    asyncio.run(exercise())


def test_decoder_ignores_malformed_ipv6_after_base64_decoding() -> None:
    """Catches a malformed decoded URI that previously aborted the whole collector run."""
    malformed = "vless://123e4567-e89b-12d3-a456-426614174000@[broken:443?security=tls"
    payload = base64.b64encode(f"{malformed}\n{VLESS_SECURE}\n".encode()).decode()
    assert extract_candidate_lines(payload) == [VLESS_SECURE]


def test_input_reader_converts_malformed_ipv6_url_to_input_error(tmp_path: Path) -> None:
    """Catches a malformed input source URL escaping the CLI's documented InputError contract."""
    source_file = tmp_path / "input.txt"
    source_file.write_text("https://[broken\n", encoding="utf-8")
    with pytest.raises(InputError):
        read_input_urls(source_file)


def test_fetcher_keeps_other_sources_when_redirect_location_is_malformed() -> None:
    """Catches one malformed redirect URL aborting collection from unrelated valid sources."""

    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "broken.example":
                return httpx.Response(302, headers={"Location": "https://[broken"})
            return httpx.Response(200, text=VLESS_SECURE)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://broken.example/list", "https://good.example/list"],
                client,
                datetime.now(UTC),
            )
        assert [result.freshness for result in results] == [Freshness.FAILED, Freshness.UNKNOWN]
        assert results[0].reason == "redirect_invalid_location"
        assert results[1].text == VLESS_SECURE

    asyncio.run(exercise())
