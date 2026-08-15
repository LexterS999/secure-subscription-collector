import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from subscription_collector import cli
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


def test_candidate_then_approved_channel_publishes_only_preview_profiles(
    tmp_path: Path,
    config_for,
) -> None:
    seed = SAFE_VLESS.replace("#preview", "#@quality_channel")
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/sub\n", encoding="utf-8")
    config = config_for(input_path=input_path)
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.host == "seed.example":
            return httpx.Response(200, text=seed)
        if request.url.host == "t.me":
            return httpx.Response(200, text=_preview_html())
        raise AssertionError(f"unexpected request: {request.url}")

    async def exercise() -> tuple[int, int, int, str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = await run_collection(config=config, client=client)
            first_output = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
            second = await run_collection(config=config, client=client)
            third = await run_collection(config=config, client=client)
        return first, second, third, first_output

    first_code, second_code, third_code, first_output = asyncio.run(exercise())
    published = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    report = json.loads(config.paths.report_path.read_text(encoding="utf-8"))

    assert (first_code, second_code, third_code) == (0, 0, 0)
    assert first_output == ""
    assert published.startswith("vless://")
    assert config.telegram.registry_path.read_text(encoding="utf-8") == "@quality_channel\n"
    assert "https://t.me/s/quality_channel?before=19" in requests
    assert report["telegram"]["discovered_channels"] == 1
    assert report["telegram"]["approved_channels"] == 1
    assert config.telegram.state_path.is_file()


def test_owned_client_stays_open_for_approved_channel_pagination(
    tmp_path: Path,
    config_for,
    monkeypatch,
) -> None:
    seed = SAFE_VLESS.replace("#preview", "#@quality_channel")
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/sub\n", encoding="utf-8")
    config = config_for(input_path=input_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "seed.example":
            return httpx.Response(200, text=seed)
        return httpx.Response(200, text=_preview_html())

    created_clients: list[httpx.AsyncClient] = []

    def mock_default_client(_settings):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        created_clients.append(client)
        return client

    monkeypatch.setattr(cli, "default_client", mock_default_client)

    async def exercise() -> tuple[int, int, int]:
        first = await run_collection(config=config)
        second = await run_collection(config=config)
        third = await run_collection(config=config)
        return first, second, third

    assert asyncio.run(exercise()) == (0, 0, 0)
    assert all(client.is_closed for client in created_clients)


def test_content_excluded_channel_is_reevaluated_when_its_public_preview_improves(
    tmp_path: Path,
    config_for,
) -> None:
    seed = SAFE_VLESS.replace("#preview", "#@quality_channel")
    input_path = tmp_path / "input.txt"
    input_path.write_text("https://seed.example/sub\n", encoding="utf-8")
    config = config_for(input_path=input_path)
    response_mode = "low_quality"
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    low_quality_preview = (
        '<div class="tgme_widget_message" data-post="quality_channel/20">'
        f'<div class="tgme_widget_message_text">{SAFE_VLESS}</div>'
        f'<time datetime="{published_at}"></time></div>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "seed.example":
            return httpx.Response(200, text=seed)
        return httpx.Response(
            200,
            text=low_quality_preview if response_mode == "low_quality" else _preview_html(),
        )

    async def exercise() -> None:
        nonlocal response_mode
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await run_collection(config=config, client=client)
            await run_collection(config=config, client=client)
            response_mode = "healthy"
            await run_collection(config=config, client=client)

    asyncio.run(exercise())
    published = (config.paths.output_dir / "vless.txt").read_text(encoding="utf-8")
    state = json.loads(config.telegram.state_path.read_text(encoding="utf-8"))
    record = next(iter(state["channels"].values()))

    assert published.count("\n") == 2
    assert record["status"] == "approved"
