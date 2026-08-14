from __future__ import annotations

import asyncio
import json
import logging

import httpx

from subscription_collector.cli import run_collection
from subscription_collector.models import ProbeResult

TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source-name"
)


def test_collection_logs_russian_progress_error_and_redacts_profile_data(tmp_path, caplog) -> None:
    """Catches an opaque pipeline or a log that reveals a profile's credentials or endpoint."""

    async def exercise() -> tuple[int, dict[str, object]]:
        input_path = tmp_path / "input.txt"
        output_path = tmp_path / "output.txt"
        report_path = tmp_path / "report.json"
        state_path = tmp_path / "state.json"
        input_path.write_text("https://source.example/list\n", encoding="utf-8")
        rejected = TROJAN_TLS.replace("node.example.org", "timeout.example.org")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=f"{TROJAN_TLS}\n{rejected}\n")

        async def fake_probe(profile):
            if profile.server == "node.example.org":
                return ProbeResult(True, 2, 41)
            return ProbeResult(False, 0, None, "timeout")

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
                probe_concurrency=2,
            )
        return code, json.loads(report_path.read_text(encoding="utf-8"))

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code, report = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert code == 0
    assert "Этап «Загрузка источников»: начат" in messages
    assert "Этап «Статическая фильтрация»: завершён" in messages
    assert "Этап «Удаление повторов»: завершён" in messages
    assert "Этап «URL-проверка»: прогресс 2/2" in messages
    assert "отклонён: тайм-аут URL-проверки" in messages
    assert "Этап «Публикация»: завершён" in messages
    assert "correct-horse" not in messages
    assert "node.example.org" not in messages
    assert report["counts"]["validation_passed"] == 1
    assert set(report["timing_ms"]) >= {
        "sources_fetch",
        "static_filter",
        "deduplication",
        "profile_validation",
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
            output_path=tmp_path / "output.txt",
            report_path=tmp_path / "report.json",
            state_path=tmp_path / "state.json",
            max_age_hours=72,
            strict_first_seen=False,
            fail_on_empty=False,
            verify_profiles=False,
        )

    caplog.set_level(logging.INFO, logger="subscription_collector.cli")
    code = asyncio.run(exercise())
    messages = "\n".join(record.getMessage() for record in caplog.records)

    assert code == 2
    assert "Этап «Подготовка»: ошибка входного файла" in messages
    assert "разрешены только HTTPS-адреса без учётных данных" in messages
    assert "private.example" not in messages
    assert "secret-token" not in messages
