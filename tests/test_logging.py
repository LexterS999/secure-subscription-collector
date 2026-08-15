from __future__ import annotations

import asyncio
import json
import logging

import httpx

from subscription_collector import cli
from subscription_collector.cli import run_collection
from subscription_collector.models import ProbeResult

TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)


def test_collection_logs_russian_progress_and_redacts_profile_data(
    tmp_path, caplog, monkeypatch
) -> None:
    """Reports safe aggregate progress and redacts data while Xray validation is active."""

    async def validated(profiles, *_args, **_kwargs) -> list[ProbeResult]:
        return [ProbeResult(True, 1, 8) for _ in profiles]

    monkeypatch.setattr(cli, "probe_batch", validated)

    async def exercise() -> tuple[int, dict[str, object]]:
        input_path = tmp_path / "input.txt"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        second = TROJAN_TLS.replace("node.example.org", "second.example.org")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=f"{TROJAN_TLS}\n{second}\n")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            code = await run_collection(
                input_path=input_path,
                output_dir=tmp_path / "output",
                report_path=report_path,
                state_path=state_path,
                max_age_hours=72,
                strict_first_seen=False,
                fail_on_empty=False,
                xray_path=tmp_path / "xray",
                client=client,
            )
        return code, json.loads(report_path.read_text(encoding="utf-8"))

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code, report = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert code == 0
    assert "Этап «Загрузка источников»: начат" in messages
    assert "Этап «Статическая фильтрация»: завершён" in messages
    assert "Этап «Удаление повторов»: завершён" in messages
    assert "Этап «Xray IP-проверка»: завершён" in messages
    assert "Этап «Публикация»: завершён" in messages
    assert "URL-проверка" not in messages
    assert "профиль №" not in messages
    assert "correct-horse" not in messages
    assert "node.example.org" not in messages
    assert "second.example.org" not in messages
    assert report["publication"]["protocols"]["trojan"] == {"new": 2, "total": 2}
    assert report["counts"]["probed_profiles"] == 2
    assert report["counts"]["validated_profiles"] == 2
    assert set(report["timing_ms"]) >= {
        "sources_fetch",
        "static_filter",
        "deduplication",
        "xray_ip_validation",
        "publication",
        "total",
    }
    assert all(value >= 0 for value in report["timing_ms"].values())


def test_collection_logs_input_error_in_russian_without_echoing_invalid_url(
    tmp_path, caplog
) -> None:
    """Catches logging of raw invalid input instead of a safe, actionable Russian explanation."""

    async def exercise() -> int:
        input_path = tmp_path / "input.txt"
        input_path.write_text("http://private.example/secret-token\n", encoding="utf-8")
        return await run_collection(
            input_path=input_path,
            output_dir=tmp_path / "output",
            report_path=tmp_path / "report.json",
            state_path=tmp_path / "state.json",
            max_age_hours=72,
            strict_first_seen=False,
            fail_on_empty=False,
            xray_path=tmp_path / "xray",
        )

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert code == 2
    assert "Этап «Подготовка»: ошибка входного файла" in messages
    assert "разрешены только HTTPS-адреса без учётных данных" in messages
    assert "private.example" not in messages
    assert "secret-token" not in messages


def test_configured_logging_keeps_pipeline_actions_and_suppresses_http_requests(caplog) -> None:
    """Catches transport INFO records that drown out the collector's completed actions."""
    from subscription_collector.cli import configure_logging

    configure_logging()
    caplog.set_level(logging.INFO)
    logging.getLogger("httpx").info(
        'HTTP Request: GET https://www.google.com/generate_204 "HTTP/1.1 204 No Content"'
    )
    logging.getLogger("httpcore").info("receive_response_headers.complete")
    logging.getLogger("subscription_collector.cli").info("Этап «Публикация»: завершён.")

    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert "Этап «Публикация»: завершён." in messages
    assert "HTTP Request:" not in messages
    assert "receive_response_headers.complete" not in messages
