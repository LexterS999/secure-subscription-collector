from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

from subscription_collector import cli, dedup
from subscription_collector.parser import parse_profile

TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)


def test_collection_reuses_each_profile_fingerprint_after_deduplication(
    tmp_path, monkeypatch, config_for
) -> None:
    """Catches repeated fingerprint work after the exact-deduplication boundary."""
    original_fingerprint = cli.profile_fingerprint
    calls = 0

    def counted_fingerprint(profile):
        nonlocal calls
        calls += 1
        return original_fingerprint(profile)

    async def exercise() -> tuple[int, str]:
        input_path = tmp_path / "input.txt"
        output_dir = tmp_path / "output"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        seed = TROJAN_TLS.replace("#source-name", "#@quality_channel")
        second = TROJAN_TLS.replace("node.example.org", "second.example.org")
        published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        preview = (
            '<div class="tgme_widget_message" data-post="quality_channel/20">'
            f'<div class="tgme_widget_message_text">{TROJAN_TLS}</div>'
            f'<time datetime="{published_at}"></time></div>'
            '<div class="tgme_widget_message" data-post="quality_channel/19">'
            f'<div class="tgme_widget_message_text">{second}</div>'
            f'<time datetime="{published_at}"></time></div>'
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text=seed if request.url.host == "source.example" else preview
            )

        config = config_for(
            input_path=input_path,
            output_dir=output_dir,
            report_path=report_path,
            state_path=state_path,
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await cli.run_collection(config=config, client=client)
            code = await cli.run_collection(config=config, client=client)
        return code, (output_dir / "trojan.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(cli, "profile_fingerprint", counted_fingerprint)
    code, output = asyncio.run(exercise())

    assert code == 0
    assert output.count("TR-TLS-TCP-") == 2
    assert calls <= 12


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
