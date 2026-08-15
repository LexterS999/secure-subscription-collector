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
from subscription_collector.fetcher import fetch_sources
from subscription_collector.input_reader import InputError, read_input_urls
from subscription_collector.models import Freshness
from subscription_collector.state import update_state
from subscription_collector.writer import write_text_atomic

VLESS_SECURE = (
    "vless://123e4567-e89b-12d3-a456-426614174000@edge.example.org:443"
    "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=grpc#source"
)


def test_input_reader_accepts_distinct_https_urls_and_ignores_comments(tmp_path: Path) -> None:
    """Catches acceptance of duplicates or mishandling of user-maintained comments."""
    input_path = tmp_path / "input.txt"
    input_path.write_text(
        "# comment\nhttps://a.example/sub\nhttps://a.example/sub\nhttps://b.example/list # label\n",
        encoding="utf-8",
    )
    assert read_input_urls(input_path) == ["https://a.example/sub", "https://b.example/list"]


@pytest.mark.parametrize(
    "line", ["http://a.example/list", "https://[broken", "https:///missing-host"]
)
def test_input_reader_rejects_invalid_source_url(tmp_path: Path, line: str) -> None:
    """Catches malformed or insecure source URLs escaping the public input contract."""
    input_path = tmp_path / "input.txt"
    input_path.write_text(f"{line}\n", encoding="utf-8")
    with pytest.raises(InputError):
        read_input_urls(input_path)


def test_decoder_extracts_allowed_uri_from_base64_and_skips_malformed_line() -> None:
    """Catches a malformed encoded URI aborting extraction of valid subsequent profiles."""
    malformed = "vless://123e4567-e89b-12d3-a456-426614174000@[broken:443?security=tls"
    payload = base64.b64encode(f"{malformed}\n{VLESS_SECURE}\n".encode()).decode()
    assert extract_candidate_lines(payload) == [VLESS_SECURE]


@pytest.mark.parametrize("scheme", ["vmess", "ss", "wireguard", "naive", "http", "socks5"])
def test_decoder_excludes_non_approved_schemes(scheme: str) -> None:
    """Catches publication of a scheme removed from the approved profile scope."""
    assert extract_candidate_lines(f"{scheme}://example\n") == []


def test_fetcher_excludes_source_with_last_modified_older_than_72_hours(config_for) -> None:
    """Catches a missing or off-by-one source freshness exclusion."""

    async def exercise() -> None:
        old = datetime.now(UTC) - timedelta(hours=72, seconds=1)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Last-Modified": old.strftime("%a, %d %b %Y %H:%M:%S GMT")},
                text=VLESS_SECURE,
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await fetch_sources(
                ["https://source.example/list"], client, datetime.now(UTC), config_for().sources
            )
        assert result[0].freshness is Freshness.STALE
        assert result[0].text is None

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("http://downgrade.example/list", "redirect_non_https"),
        ("https://user:pass@redirect.example/list", "redirect_credentials"),
        ("https://[broken", "redirect_invalid_location"),
    ],
)
def test_fetcher_rejects_unsafe_redirect_before_following(
    location: str, reason: str, config_for
) -> None:
    """Catches redirects that would lower transport security or inject malformed credentials."""

    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(302, headers={"Location": location})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await fetch_sources(
                ["https://source.example/list"], client, datetime.now(UTC), config_for().sources
            )
        assert results[0].freshness is Freshness.FAILED
        assert results[0].reason == reason
        assert requests == ["https://source.example/list"]

    asyncio.run(exercise())


def test_state_retains_prior_first_seen_records(tmp_path: Path) -> None:
    """Catches loss of first-seen history when a profile misses one collection run."""
    state_path = tmp_path / "state.json"
    first = "a" * 64
    second = "b" * 64
    initial = datetime(2026, 8, 14, 12, tzinfo=UTC)
    update_state(state_path, [first], initial)
    state = update_state(state_path, [second], initial + timedelta(hours=1))
    assert state[first].first_seen_at == "2026-08-14T12:00:00Z"
    assert state[second].first_seen_at == "2026-08-14T13:00:00Z"


def test_atomic_writer_replaces_previous_contents(tmp_path: Path) -> None:
    """Catches incomplete replacement in the low-level atomic text writer."""
    output_path = tmp_path / "result.txt"
    output_path.write_text("old\n", encoding="utf-8")
    write_text_atomic(output_path, "new\n")
    assert output_path.read_text(encoding="utf-8") == "new\n"


def test_collection_publishes_preview_profiles_without_network_probe(
    tmp_path: Path, config_for
) -> None:
    """A quality-approved channel publishes strict profiles without calling probe endpoints."""
    seed = VLESS_SECURE.replace("#source", "#@quality_channel")
    second = VLESS_SECURE.replace("edge.example.org", "second.example.org")
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://source.example/list\n", encoding="utf-8")
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    preview = (
        '<div class="tgme_widget_message" data-post="quality_channel/20">'
        f'<div class="tgme_widget_message_text">{VLESS_SECURE}</div>'
        f'<time datetime="{published_at}"></time></div>'
        '<div class="tgme_widget_message" data-post="quality_channel/19">'
        f'<div class="tgme_widget_message_text">{second}</div>'
        f'<time datetime="{published_at}"></time></div>'
    )
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host or "")
        if request.url.host == "source.example":
            return httpx.Response(200, text=seed)
        if request.url.host == "t.me":
            return httpx.Response(200, text=preview)
        raise AssertionError(f"unexpected network request: {request.url}")

    async def exercise() -> tuple[int, int, str]:
        config = config_for(input_path=input_path)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = await run_collection(config=config, client=client)
            first_output = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
            second_run = await run_collection(config=config, client=client)
        return first, second_run, first_output

    first_code, second_code, first_output = asyncio.run(exercise())
    output = (tmp_path / "output" / "vless.txt").read_text(encoding="utf-8")
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert (first_code, second_code) == (0, 0)
    assert first_output == ""
    assert output.count("\n") == 2
    assert set(requested_hosts) <= {"source.example", "t.me"}
    assert "probed_profiles" not in report["counts"]
    assert "validated_profiles" not in report["counts"]


def test_collection_does_not_publish_policy_rejected_preview_profile(
    tmp_path: Path, config_for
) -> None:
    """The removal of Xray must not weaken strict security policy filtering."""
    seed = VLESS_SECURE.replace("#source", "#@quality_channel")
    unsafe = VLESS_SECURE.replace("security=tls", "security=tls&allowInsecure=1")
    unsafe_second = unsafe.replace(
        "123e4567-e89b-12d3-a456-426614174000", "223e4567-e89b-12d3-a456-426614174000"
    )
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://source.example/list\n", encoding="utf-8")
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    preview = (
        '<div class="tgme_widget_message" data-post="quality_channel/20">'
        f'<div class="tgme_widget_message_text">{unsafe}</div>'
        f'<time datetime="{published_at}"></time></div>'
        '<div class="tgme_widget_message" data-post="quality_channel/19">'
        f'<div class="tgme_widget_message_text">{unsafe_second}</div>'
        f'<time datetime="{published_at}"></time></div>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=seed if request.url.host == "source.example" else preview)

    async def exercise() -> None:
        config = config_for(input_path=input_path)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await run_collection(config=config, client=client)
            await run_collection(config=config, client=client)
        assert (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8") == ""

    asyncio.run(exercise())
