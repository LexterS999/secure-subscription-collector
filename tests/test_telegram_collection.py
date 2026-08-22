import asyncio
import json
import logging
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from subscription_collector.cli import run_collection

SAFE_VLESS = (
    "vless://123e4567-e89b-12d3-a456-426614174000@edge.example.org:443"
    "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=grpc#preview"
)
SAFE_VLESS_SECOND = (
    "vless://223e4567-e89b-12d3-a456-426614174000@edge-two.example.org:443"
    "?encryption=none&security=tls&sni=www.example.net&fp=chrome&type=grpc#preview-two"
)


def _preview_html() -> str:
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f"""
    <div class="tgme_widget_message" data-post="quality_channel/20">
      <div class="tgme_widget_message_text">{SAFE_VLESS}</div>
      <time datetime="{published_at}"></time>
    </div>
    <div class="tgme_widget_message" data-post="quality_channel/19">
      <div class="tgme_widget_message_text">{SAFE_VLESS_SECOND}</div>
      <time datetime="{published_at}"></time>
    </div>
    """


def test_public_preview_profiles_pass_full_analysis_and_approve_quality_channel(
    tmp_path: Path,
    config_for,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catch a Telegram path that bypasses filtering or never writes its quality outcome."""
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/sub\n", encoding="utf-8")
    config = config_for(input_path=input_path)
    requests: list[str] = []
    seed = SAFE_VLESS.replace(
        "123e4567-e89b-12d3-a456-426614174000",
        "323e4567-e89b-12d3-a456-426614174000",
    ).replace("#preview", "#@quality_channel")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.host == "seed.example":
            return httpx.Response(200, text=seed)
        if request.url.host == "t.me":
            return httpx.Response(200, text=_preview_html())
        raise AssertionError(f"unexpected request: {request.url}")

    async def exercise() -> tuple[int, int]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = await run_collection(config=config, client=client)
            second = await run_collection(config=config, client=client)
        return first, second

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    assert asyncio.run(exercise()) == (0, 0)
    published = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    report = json.loads(config.paths.report_path.read_text(encoding="utf-8"))

    assert published.count("\n") == 2
    assert "323e4567-e89b-12d3-a456-426614174000" not in published
    assert "123e4567-e89b-12d3-a456-426614174000" in published
    assert "223e4567-e89b-12d3-a456-426614174000" in published
    assert config.paths.tg_channels_path.read_text(encoding="utf-8") == "@quality_channel\n"
    assert "quality_channel" not in config.paths.telegram_state_path.read_text(encoding="utf-8")
    telegram_report = report["telegram"]
    assert telegram_report["discovered_channels"] == 1
    assert telegram_report["approved_channels"] == 1
    assert telegram_report["uri_candidates"] == 2
    assert telegram_report["static_accepted_profiles"] == 2
    assert telegram_report["unique_profiles"] == 2
    assert telegram_report["deep_accepted_profiles"] == 2
    assert (
        "Telegram: обнаружено публичных каналов: 1; свежих сообщений за 72 ч: 2; "
        "URI-кандидатов: 2." in "\n".join(record.getMessage() for record in caplog.records)
    )
    assert "https://t.me/s/quality_channel" in requests


SAFE_TROJAN = (
    "trojan://correct-horse@trojan.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#preview-trojan"
)
SAFE_HYSTERIA2 = (
    "hy2://correct-horse@hy2.example.org:443?security=tls&sni=www.example.com&alpn=h3#preview-hy2"
)


def test_public_preview_publishes_all_supported_protocols_only_from_telegram(
    tmp_path: Path,
    config_for,
) -> None:
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/all-protocols\n", encoding="utf-8")
    config = config_for(input_path=input_path)
    direct_vless = SAFE_VLESS.replace(
        "123e4567-e89b-12d3-a456-426614174000",
        "323e4567-e89b-12d3-a456-426614174000",
    ).replace("#preview", "#@all_protocol_channel")
    direct_trojan = SAFE_TROJAN.replace("#preview-trojan", "#@all_protocol_channel")
    direct_hysteria2 = SAFE_HYSTERIA2.replace("#preview-hy2", "#@all_protocol_channel")
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    preview = "\n".join(
        (
            '<div class="tgme_widget_message" data-post="all_protocol_channel/3">'
            f'<div class="tgme_widget_message_text">{SAFE_VLESS}</div>'
            f'<time datetime="{published_at}"></time></div>',
            '<div class="tgme_widget_message" data-post="all_protocol_channel/2">'
            f'<div class="tgme_widget_message_text">{SAFE_TROJAN}</div>'
            f'<time datetime="{published_at}"></time></div>',
            '<div class="tgme_widget_message" data-post="all_protocol_channel/1">'
            f'<div class="tgme_widget_message_text">{SAFE_HYSTERIA2}</div>'
            f'<time datetime="{published_at}"></time></div>',
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "seed.example":
            return httpx.Response(
                200,
                text="\n".join((direct_vless, direct_trojan, direct_hysteria2)),
            )
        if request.url.host == "t.me":
            return httpx.Response(200, text=preview)
        raise AssertionError(f"unexpected request: {request.url}")

    async def exercise() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_collection(config=config, client=client)

    assert asyncio.run(exercise()) == 0
    vless_output = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    trojan_output = (config.paths.output_dir / "trojan.txt").read_text(encoding="utf-8")
    hysteria2_output = (config.paths.output_dir / "hysteria2.txt").read_text(encoding="utf-8")

    assert vless_output.count("\n") == 1
    assert trojan_output.count("\n") == 1
    assert hysteria2_output.count("\n") == 1
    assert "323e4567-e89b-12d3-a456-426614174000" not in vless_output
    assert "123e4567-e89b-12d3-a456-426614174000" in vless_output


def test_channel_profiles_are_capped_across_all_protocols(tmp_path: Path, config_for) -> None:
    """The per-channel cap bounds accepted profiles of every protocol combined."""
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/capped\n", encoding="utf-8")
    config = replace(
        config_for(input_path=input_path),
        telegram=replace(config_for().telegram, max_profiles_per_channel=1),
    )
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    preview = "\n".join(
        (
            '<div class="tgme_widget_message" data-post="capped_channel/2">'
            f'<div class="tgme_widget_message_text">{SAFE_VLESS}</div>'
            f'<time datetime="{published_at}"></time></div>',
            '<div class="tgme_widget_message" data-post="capped_channel/1">'
            f'<div class="tgme_widget_message_text">{SAFE_TROJAN}</div>'
            f'<time datetime="{published_at}"></time></div>',
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "seed.example":
            return httpx.Response(200, text="#@capped_channel\n")
        if request.url.host == "t.me":
            return httpx.Response(200, text=preview)
        raise AssertionError(f"unexpected request: {request.url}")

    async def exercise() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_collection(config=config, client=client)

    assert asyncio.run(exercise()) == 0
    vless_output = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    trojan_output = (config.paths.output_dir / "trojan.txt").read_text(encoding="utf-8")

    assert vless_output.count("\n") == 1
    assert trojan_output == ""
    report = json.loads(config.paths.report_path.read_text(encoding="utf-8"))
    assert report["telegram"]["static_accepted_profiles"] == 1


def test_collection_does_not_fetch_registry_only_channel_without_current_subscription_handle(
    tmp_path: Path,
    config_for,
) -> None:
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/no-channel\n", encoding="utf-8")
    registry_path = tmp_path / "tg_registry.txt"
    registry_path.write_text("@registry_only_channel\n", encoding="utf-8")
    config = config_for(input_path=input_path, telegram_registry_path=registry_path)
    direct_profile = SAFE_VLESS.replace("#preview", "#without_channel")
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host or "")
        if request.url.host == "seed.example":
            return httpx.Response(200, text=direct_profile)
        raise AssertionError(f"registry channel must not be fetched: {request.url}")

    async def exercise() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_collection(config=config, client=client)

    assert asyncio.run(exercise()) == 0
    assert requested_hosts == ["seed.example"]
    assert (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8").count("\n") == 1
    assert registry_path.read_text(encoding="utf-8") == ""
