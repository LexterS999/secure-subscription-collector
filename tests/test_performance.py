from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

from subscription_collector import cli, dedup
from subscription_collector.models import ProbeResult
from subscription_collector.parser import parse_profile

TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)


def test_collection_reuses_each_profile_fingerprint_after_deduplication(
    tmp_path, monkeypatch, config_for
) -> None:
    """Catches repeated JSON serialization and SHA-256 work after deduplication."""
    original_fingerprint = cli.profile_fingerprint
    calls = 0

    def counted_fingerprint(profile):
        nonlocal calls
        calls += 1
        return original_fingerprint(profile)

    async def validated(profiles, *_args, **_kwargs) -> list[ProbeResult]:
        return [ProbeResult(True, 1, 8) for _ in profiles]

    monkeypatch.setattr(cli, "probe_batch", validated)

    async def exercise() -> tuple[int, str]:
        input_path = tmp_path / "input.txt"
        output_dir = tmp_path / "output"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")

        seed = TROJAN_TLS.replace("#source-name", "#@quality_channel")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "source.example":
                return httpx.Response(200, text=seed)
            if request.url.host == "t.me":
                published_at = datetime.now(UTC).replace(microsecond=0).isoformat()
                return httpx.Response(
                    200,
                    text=(
                        '<div class="tgme_widget_message" data-post="quality_channel/1">'
                        f'<div class="tgme_widget_message_text">{TROJAN_TLS}</div>'
                        f'<time datetime="{published_at}"></time></div>'
                    ),
                )
            raise AssertionError(f"unexpected request: {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            code = await cli.run_collection(
                config=config_for(
                    input_path=input_path,
                    output_dir=output_dir,
                    report_path=report_path,
                    state_path=state_path,
                    xray_path=tmp_path / "xray",
                ),
                client=client,
            )
        return code, (output_dir / "trojan.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(cli, "profile_fingerprint", counted_fingerprint)
    code, output = asyncio.run(exercise())

    assert code == 0
    assert "TR-TLS-TCP-" in output
    assert calls == 1


def test_deduplication_uses_exact_fingerprint_without_redundant_compatibility_groups(
    monkeypatch,
) -> None:
    """Catches reintroduction of an unused grouping pass in the deduplication hot path."""
    first = parse_profile(TROJAN_TLS, "https://source.example/list")
    duplicate = parse_profile(
        "trojan://correct-horse@node.example.org:443"
        "?type=tcp&fp=chrome&sni=www.example.com&security=tls#another-name",
        "https://source.example/list",
    )
    assert first is not None and duplicate is not None

    def fail_if_called(_profile):
        raise AssertionError("Неиспользуемая compatibility-группировка не должна вызываться")

    monkeypatch.setattr(dedup, "client_compatibility_key", fail_if_called)

    assert dedup.deduplicate([first, duplicate]) == [first]
