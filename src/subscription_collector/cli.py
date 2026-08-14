from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import httpx

from .decoder import extract_candidate_lines
from .dedup import deduplicate, profile_fingerprint
from .fetcher import default_client, fetch_sources
from .input_reader import InputError, read_input_urls
from .models import ProbeResult, Profile, RunStats
from .parser import parse_profile
from .policy import evaluate_strict_secure
from .probe import probe_profile
from .renamer import render_named_uri
from .report import build_report
from .state import update_state
from .writer import write_json_atomic, write_text_atomic

ProbeRunner = Callable[[Profile], Awaitable[ProbeResult]]
logger = logging.getLogger(__name__)


def configure_logging() -> None:
    """Configure action-focused logs and suppress per-request transport noise."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for logger_name in ("httpx", "httpcore"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


_VALIDATION_ERROR_MESSAGES = {
    "binary_unavailable": "не найден файл программы проверки",
    "http_error": "ошибка HTTP-запроса",
    "listener_timeout": "истекло время запуска локального прокси",
    "process_error": "не удалось запустить программу проверки",
    "quorum": "не набран кворум ответов контрольных URL",
    "runner_error": "внутренняя ошибка запуска проверки",
    "timeout": "тайм-аут URL-проверки",
    "unexpected_status": "контрольные URL вернули неожиданный статус",
}


def _within_first_seen_window(first_seen_at: str, now: datetime, hours: int) -> bool:
    parsed = datetime.fromisoformat(first_seen_at.replace("Z", "+00:00"))
    return parsed >= now.astimezone(UTC) - timedelta(hours=hours)


def _stage_duration_ms(stats: RunStats, stage: str, started_at: float) -> int:
    duration_ms = round((perf_counter() - started_at) * 1000)
    stats.timing_ms[stage] = duration_ms
    return duration_ms


def _duration_text(duration_ms: int) -> str:
    return f"{duration_ms / 1000:.2f} с"


def _validation_error_message(error_category: str | None) -> str:
    return _VALIDATION_ERROR_MESSAGES.get(
        error_category or "quorum", "контрольные URL не прошли проверку"
    )


async def _validate_profiles(
    profiles: list[Profile],
    *,
    runner: ProbeRunner,
    concurrency: int,
    batch_size: int,
    stats: RunStats,
) -> list[Profile]:
    """Validate profiles in bounded asynchronous batches with safe Russian progress logs."""
    if not profiles:
        logger.info("Этап «URL-проверка»: пропущен — нет профилей для проверки.")
        return []

    worker_count = min(concurrency, batch_size, len(profiles))
    logger.info(
        "Этап «URL-проверка»: начат — профилей: %d, размер батча: %d, "
        "одновременных проверок: %d.",
        len(profiles),
        batch_size,
        worker_count,
    )

    async def run_batch(
        batch: list[tuple[int, Profile]],
    ) -> list[tuple[int, Profile, ProbeResult]]:
        semaphore = asyncio.Semaphore(worker_count)

        async def run_one(index: int, profile: Profile) -> tuple[int, Profile, ProbeResult]:
            async with semaphore:
                try:
                    result = await runner(profile)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    result = ProbeResult(False, 0, None, "runner_error")
            return index, profile, result

        return list(await asyncio.gather(*(run_one(index, profile) for index, profile in batch)))

    accepted_by_index: dict[int, Profile] = {}
    progress_interval = max(1, len(profiles) // 20)
    completed = 0
    indexed_profiles = list(enumerate(profiles, start=1))
    for batch_start in range(0, len(indexed_profiles), batch_size):
        batch = indexed_profiles[batch_start : batch_start + batch_size]
        for index, profile, result in await run_batch(batch):
            completed += 1
            stats.validation_attempted += 1
            if result.passed:
                stats.validation_passed += 1
                if result.median_latency_ms is not None:
                    stats.validation_median_latencies_ms.append(result.median_latency_ms)
                accepted_by_index[index] = profile
            else:
                stats.validation_failed += 1
                error_category = result.error_category or "quorum"
                stats.exclude(f"validation:{error_category}")
                logger.warning(
                    "Этап «URL-проверка»: профиль №%d отклонён: %s (успешных ответов: %d из 4).",
                    index,
                    _validation_error_message(error_category),
                    result.successes,
                )
            if completed % progress_interval == 0 or completed == len(profiles):
                logger.info(
                    "Этап «URL-проверка»: прогресс %d/%d — прошло: %d, отклонено: %d.",
                    completed,
                    len(profiles),
                    stats.validation_passed,
                    stats.validation_failed,
                )

    return [accepted_by_index[index] for index in sorted(accepted_by_index)]


async def run_collection(
    *,
    input_path: Path,
    output_path: Path,
    report_path: Path,
    state_path: Path,
    max_age_hours: int,
    strict_first_seen: bool,
    fail_on_empty: bool,
    client: httpx.AsyncClient | None = None,
    sing_box_path: Path | None = None,
    verify_profiles: bool = True,
    probe_timeout_seconds: float = 0.3,
    probe_startup_timeout_seconds: float = 3.0,
    probe_concurrency: int = 8,
    probe_batch_size: int = 32,
    probe_runner: ProbeRunner | None = None,
) -> int:
    """Collect, filter, URL-test and publish profiles without logging profile secrets."""
    started_at = datetime.now(UTC)
    monotonic_started_at = perf_counter()
    stats = RunStats()
    sources = []
    logger.info("Конвейер сбора подписок: запуск.")
    if probe_concurrency < 1:
        raise ValueError("probe_concurrency must be positive")
    if probe_batch_size < 1:
        raise ValueError("probe_batch_size must be positive")
    if probe_timeout_seconds <= 0:
        raise ValueError("probe_timeout_seconds must be positive")
    if probe_startup_timeout_seconds <= 0:
        raise ValueError("probe_startup_timeout_seconds must be positive")
    if verify_profiles and probe_runner is None and sing_box_path is None:
        logger.error(
            "Этап «Подготовка»: ошибка — не указан путь к программе проверки профилей."
        )
        write_json_atomic(
            report_path,
            {
                "generated_at": started_at.replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "policy": "Strict Secure",
                "error": "validation_binary_unavailable",
                "counts": {"emitted_profiles": 0},
            },
        )
        return 3

    logger.info("Этап «Подготовка»: начат — проверка списка источников.")
    try:
        urls = read_input_urls(input_path)
    except InputError:
        logger.error(
            "Этап «Подготовка»: ошибка входного файла — разрешены только HTTPS-адреса "
            "без учётных данных; проверьте input.txt."
        )
        write_text_atomic(output_path, "")
        write_json_atomic(
            report_path,
            {
                "generated_at": started_at.replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "policy": "Strict Secure",
                "error": "invalid_input",
                "counts": {"emitted_profiles": 0},
            },
        )
        return 2
    logger.info("Этап «Подготовка»: завершён — источников: %d.", len(urls))

    stats.input_sources = len(urls)
    fetch_started_at = perf_counter()
    logger.info("Этап «Загрузка источников»: начат — адресов: %d.", len(urls))
    owns_client = client is None
    active_client = client or default_client()
    try:
        sources = await fetch_sources(urls, active_client, started_at, max_age_hours)
    finally:
        if owns_client:
            await active_client.aclose()
    fetch_duration_ms = _stage_duration_ms(stats, "sources_fetch", fetch_started_at)
    usable_sources = sum(source.text is not None for source in sources)
    logger.info(
        "Этап «Загрузка источников»: завершён за %s — пригодных источников: %d, исключённых: %d.",
        _duration_text(fetch_duration_ms),
        usable_sources,
        len(sources) - usable_sources,
    )

    static_filter_started_at = perf_counter()
    logger.info("Этап «Статическая фильтрация»: начат.")
    accepted: list[Profile] = []
    for source in sources:
        stats.source_freshness[source.freshness.value] = (
            stats.source_freshness.get(source.freshness.value, 0) + 1
        )
        if source.text is None:
            stats.exclude(source.reason or source.freshness.value)
            continue
        stats.fetched_sources += 1
        lines = extract_candidate_lines(source.text)
        stats.candidate_lines += len(lines)
        for line in lines:
            profile = parse_profile(line, source.source_url)
            if profile is None:
                stats.exclude("invalid_or_unsupported")
                continue
            stats.parsed_profiles += 1
            decision = evaluate_strict_secure(profile)
            if decision.profile is None:
                stats.exclude(decision.reason or "policy_rejected")
                continue
            accepted.append(decision.profile)
            stats.accepted_profiles += 1
    static_filter_duration_ms = _stage_duration_ms(stats, "static_filter", static_filter_started_at)
    logger.info(
        "Этап «Статическая фильтрация»: завершён за %s — кандидатов: %d, "
        "допущено: %d, исключено: %d.",
        _duration_text(static_filter_duration_ms),
        stats.candidate_lines,
        stats.accepted_profiles,
        stats.candidate_lines - stats.accepted_profiles,
    )

    deduplication_started_at = perf_counter()
    logger.info("Этап «Удаление повторов»: начат — профилей до обработки: %d.", len(accepted))
    unique = deduplicate(accepted)
    stats.unique_profiles = len(unique)
    deduplication_duration_ms = _stage_duration_ms(stats, "deduplication", deduplication_started_at)
    logger.info(
        "Этап «Удаление повторов»: завершён за %s — уникальных: %d, удалено повторов: %d.",
        _duration_text(deduplication_duration_ms),
        stats.unique_profiles,
        len(accepted) - stats.unique_profiles,
    )

    if verify_profiles:
        if probe_runner is None:
            assert sing_box_path is not None

            async def probe_runner(profile: Profile) -> ProbeResult:
                return await probe_profile(
                    profile,
                    sing_box_path,
                    timeout_seconds=probe_timeout_seconds,
                    startup_timeout_seconds=probe_startup_timeout_seconds,
                )

        profile_validation_started_at = perf_counter()
        unique = await _validate_profiles(
            unique,
            runner=probe_runner,
            concurrency=probe_concurrency,
            batch_size=probe_batch_size,
            stats=stats,
        )
        profile_validation_duration_ms = _stage_duration_ms(
            stats, "profile_validation", profile_validation_started_at
        )
        logger.info(
            "Этап «URL-проверка»: завершён за %s — прошло: %d, отклонено: %d.",
            _duration_text(profile_validation_duration_ms),
            stats.validation_passed,
            stats.validation_failed,
        )
    else:
        stats.timing_ms["profile_validation"] = 0
        logger.info("Этап «URL-проверка»: отключён параметром запуска.")

    publication_started_at = perf_counter()
    logger.info("Этап «Публикация»: начат.")
    fingerprints_by_profile_id = {
        id(profile): profile_fingerprint(profile) for profile in unique
    }
    state = update_state(state_path, list(fingerprints_by_profile_id.values()), started_at)
    profiles = list(unique)
    if strict_first_seen:
        profiles = [
            profile
            for profile in profiles
            if _within_first_seen_window(
                state[fingerprints_by_profile_id[id(profile)]].first_seen_at,
                started_at,
                max_age_hours,
            )
        ]
    profiles.sort(
        key=lambda item: (
            item.protocol.value,
            item.security,
            item.transport,
            fingerprints_by_profile_id[id(item)],
        )
    )
    output_lines = [
        render_named_uri(profile, fingerprints_by_profile_id[id(profile)]) for profile in profiles
    ]
    stats.emitted_profiles = len(output_lines)
    _stage_duration_ms(stats, "publication", publication_started_at)
    stats.timing_ms["total"] = round((perf_counter() - monotonic_started_at) * 1000)
    try:
        write_text_atomic(output_path, "\n".join(output_lines) + ("\n" if output_lines else ""))
        write_json_atomic(
            report_path,
            build_report(
                started_at=started_at,
                sources=sources,
                stats=stats,
                max_age_hours=max_age_hours,
                strict_first_seen=strict_first_seen,
                verification_enabled=verify_profiles,
            ),
        )
    except OSError:
        logger.error(
            "Этап «Публикация»: ошибка записи результата. "
            "Проверьте права доступа и свободное место."
        )
        raise
    logger.info(
        "Этап «Публикация»: завершён — опубликовано профилей: %d. Конвейер завершён за %s.",
        stats.emitted_profiles,
        _duration_text(stats.timing_ms["total"]),
    )
    return 2 if fail_on_empty and not output_lines else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect validated VLESS, Trojan, Hysteria2 and TUIC profiles"
    )
    parser.add_argument("--input", type=Path, default=Path("input.txt"))
    parser.add_argument("--output", type=Path, default=Path("output.txt"))
    parser.add_argument("--report", type=Path, default=Path("report.json"))
    parser.add_argument("--state", type=Path, default=Path(".collector/state.json"))
    parser.add_argument("--max-age-hours", type=int, default=72)
    parser.add_argument("--strict-first-seen", action="store_true")
    parser.add_argument("--fail-on-empty", action="store_true")
    parser.add_argument("--sing-box-path", type=Path)
    parser.add_argument("--no-verify-profiles", action="store_true")
    parser.add_argument(
        "--probe-timeout-seconds",
        type=float,
        default=0.3,
        help="maximum duration in seconds for one control URL response through a profile",
    )
    parser.add_argument(
        "--probe-startup-timeout-seconds",
        type=float,
        default=3.0,
        help="maximum duration in seconds for starting a temporary profile proxy",
    )
    parser.add_argument("--probe-concurrency", type=int, default=8)
    parser.add_argument("--probe-batch-size", type=int, default=32)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    return asyncio.run(
        run_collection(
            input_path=args.input,
            output_path=args.output,
            report_path=args.report,
            state_path=args.state,
            max_age_hours=args.max_age_hours,
            strict_first_seen=args.strict_first_seen,
            fail_on_empty=args.fail_on_empty,
            sing_box_path=args.sing_box_path,
            verify_profiles=not args.no_verify_profiles,
            probe_timeout_seconds=args.probe_timeout_seconds,
            probe_startup_timeout_seconds=args.probe_startup_timeout_seconds,
            probe_concurrency=args.probe_concurrency,
            probe_batch_size=args.probe_batch_size,
        )
    )
