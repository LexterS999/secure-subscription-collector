import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from subscription_collector import cli
from subscription_collector.cli import run_collection
from subscription_collector.models import ProbeResult

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


def test_public_preview_profiles_share_xray_validation_and_approve_quality_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_for,
) -> None:
    """Catch a Telegram path that bypasses filtering or never writes its quality outcome."""

    async def validated(profiles, *_args, **_kwargs) -> list[ProbeResult]:
        return [ProbeResult(True, 1, 8) for _ in profiles]

    monkeypatch.setattr(cli, "probe_batch", validated)
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

    assert asyncio.run(exercise()) == (0, 0)
    published = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    report = json.loads(config.paths.report_path.read_text(encoding="utf-8"))

    assert published.count("\n") == 3
    assert config.paths.tg_channels_path.read_text(encoding="utf-8") == "@quality_channel\n"
    assert "quality_channel" not in config.paths.telegram_state_path.read_text(encoding="utf-8")
    assert report["telegram"]["discovered_channels"] == 1
    assert report["telegram"]["approved_channels"] == 1
    assert "https://t.me/s/quality_channel" in requests
