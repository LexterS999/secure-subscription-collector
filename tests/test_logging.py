import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx

from subscription_collector.cli import run_collection

TROJAN_TLS = (
    "trojan://correct-horse-battery-staple@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome#source-name"
)


def _preview_posts(first: str, second: str) -> str:
    published_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return (
        '<div class="tgme_widget_message" data-post="quality_channel/20">'
        f'<div class="tgme_widget_message_text">{first}</div>'
        f'<time datetime="{published_at}"></time></div>'
        '<div class="tgme_widget_message" data-post="quality_channel/19">'
        f'<div class="tgme_widget_message_text">{second}</div>'
        f'<time datetime="{published_at}"></time></div>'
    )


def test_collection_logs_redacted_content_quality_stages(
    tmp_path: Path, caplog, config_for
) -> None:
    async def exercise() -> tuple[int, dict[str, object]]:
        input_path = tmp_path / "input.txt"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        seed = TROJAN_TLS.replace("#source-name", "#@quality_channel")
        second = TROJAN_TLS.replace("node.example.org", "second.example.org")
        preview = _preview_posts(TROJAN_TLS, second)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text=seed if request.url.host == "source.example" else preview
            )

        config = config_for(
            input_path=input_path,
            report_path=report_path,
            state_path=state_path,
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await run_collection(config=config, client=client)
            code = await run_collection(config=config, client=client)
        return code, json.loads(report_path.read_text(encoding="utf-8"))

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code, report = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)
    timings = report["timing_ms"]
    counts = report["counts"]

    assert code == 0
    assert "Этап «Загрузка seed-источников»: начат" in messages
    assert "Этап «Discovery Telegram»: обнаружено каналов: 1." in messages
    assert "Этап «Публикация»: завершён" in messages
    assert "Xray" not in messages
    assert "URL-проверка" not in messages
    assert "профиль №" not in messages
    assert "correct-horse" not in messages
    assert "node.example.org" not in messages
    assert "second.example.org" not in messages
    assert report["publication"]["protocols"]["trojan"] == {"new": 2, "total": 2}
    assert "probed_profiles" not in counts
    assert "validated_profiles" not in counts
    assert report["telegram"]["approved_channels"] == 1
    assert set(timings) >= {
        "sources_fetch",
        "telegram_discovery",
        "telegram_preview_fetch",
        "deduplication",
        "channel_quality",
        "publication",
        "total",
    }
    assert "xray_ip_validation" not in timings
    assert all(value >= 0 for value in timings.values())


def test_collection_logs_input_error_in_russian_without_echoing_invalid_url(
    tmp_path: Path, caplog, config_for
) -> None:
    async def exercise() -> int:
        input_path = tmp_path / "input.txt"
        input_path.write_text("http://private.example/secret-token\n", encoding="utf-8")
        return await run_collection(config=config_for(input_path=input_path))

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert code == 2
    assert "Этап «Подготовка»: ошибка входного файла" in messages
    assert "разрешены только HTTPS-адреса без учётных данных" in messages
    assert "private.example" not in messages
    assert "secret-token" not in messages


def test_configured_logging_keeps_pipeline_actions_and_suppresses_http_requests(caplog) -> None:
    from subscription_collector.cli import configure_logging

    configure_logging()
    caplog.set_level(logging.INFO)
    logging.getLogger("httpx").info(
        'HTTP Request: GET https://example.invalid "HTTP/1.1 204 No Content"'
    )
    logging.getLogger("httpcore").info("receive_response_headers.complete")
    logging.getLogger("subscription_collector.cli").info("Этап «Публикация»: завершён.")
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert "Этап «Публикация»: завершён." in messages
    assert "HTTP Request:" not in messages
    assert "receive_response_headers.complete" not in messages
