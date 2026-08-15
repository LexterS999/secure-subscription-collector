from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import httpx

from .decoder import extract_candidate_lines
from .dedup import deduplicate, profile_fingerprint
from .fetcher import default_client, fetch_sources
from .input_reader import InputError, read_input_urls
from .models import ProbeResult, Profile, RunStats
from .output_store import publish_profiles
from .parser import parse_profile
from .policy import evaluate_strict_secure
from .probe import probe_batch, tcp_precheck
from .report import build_report
from .state import update_state
from .writer import write_json_atomic

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


def _within_first_seen_window(first_seen_at: str, now: datetime, hours: int) -> bool:
    parsed = datetime.fromisoformat(first_seen_at.replace("Z", "+00:00"))
    return parsed >= now.astimezone(UTC) - timedelta(hours=hours)


def _stage_duration_ms(stats: RunStats, stage: str, started_at: float) -> int:
    duration_ms = round((perf_counter() - started_at) * 1000)
    stats.timing_ms[stage] = duration_ms
    return duration_ms


def _duration_text(duration_ms: int) -> str:
    return f"{duration_ms / 1000:.2f} с"


def _parse_and_filter_candidate(
    line: str, source_url: str
) -> tuple[Profile | None, bool, str | None]:
    """Apply CPU-bound URI parsing and the strict policy without mutating shared statistics."""
    profile = parse_profile(line, source_url)
    if profile is None:
        return None, False, "invalid_or_unsupported"
    decision = evaluate_strict_secure(profile)
    if decision.profile is None:
        return None, True, decision.reason or "policy_rejected"
    return decision.profile, True, None


async def _filter_tcp_reachable_profiles(
    profiles: Sequence[Profile],
    *,
    runner: Callable[[Profile], Awaitable[str | None]],
    concurrency: int,
    stats: RunStats,
) -> list[Profile]:
    """Exclude TCP-unreachable profiles before allocating an Xray batch; keep QUIC profiles."""
    if concurrency < 1:
        raise ValueError("tcp_precheck_concurrency must be positive")
    semaphore = asyncio.Semaphore(concurrency)

    async def check(profile: Profile) -> tuple[Profile, str | None]:
        async with semaphore:
            try:
                return profile, await runner(profile)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                    raise
                return profile, "tcp_precheck_error"

    outcomes = await asyncio.gather(*(check(profile) for profile in profiles))
    kept: list[Profile] = []
    for profile, category in outcomes:
        if category is None:
            kept.append(profile)
        else:
            stats.exclude(category)
    return kept


async def _validate_profiles(
    profiles: Sequence[Profile],
    *,
    batch_runner: Callable[[Sequence[Profile]], Awaitable[Sequence[ProbeResult]]],
    batch_concurrency: int,
    batch_size: int,
    stats: RunStats,
) -> list[Profile]:
    """Run bounded Xray batches and return only profiles with a successful public-IP response."""
    if batch_concurrency < 1:
        raise ValueError("probe_batch_concurrency must be positive")
    if batch_size < 1:
        raise ValueError("probe_batch_size must be positive")

    batches = [
        profiles[start : start + batch_size]
        for start in range(0, len(profiles), batch_size)
    ]
    semaphore = asyncio.Semaphore(batch_concurrency)

    async def validate_batch(
        batch_index: int, batch: Sequence[Profile]
    ) -> tuple[int, Sequence[Profile], list[ProbeResult]]:
        async with semaphore:
            try:
                results = list(await batch_runner(batch))
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                    raise
                results = [ProbeResult(False, 0, None, "batch_runner_error") for _ in batch]
            if len(results) != len(batch):
                results = [ProbeResult(False, 0, None, "batch_result_mismatch") for _ in batch]
            return batch_index, batch, results

    completed_batches = await asyncio.gather(
        *(validate_batch(index, batch) for index, batch in enumerate(batches))
    )
    accepted: list[Profile] = []
    for _, batch, results in sorted(completed_batches, key=lambda item: item[0]):
        for profile, result in zip(batch, results, strict=True):
            stats.probed_profiles += 1
            if result.passed:
                accepted.append(profile)
                stats.validated_profiles += 1
            else:
                stats.exclude(result.error_category or "ip_validation_failed")
    return accepted


async def run_collection(
    *,
    input_path: Path,
    output_dir: Path,
    report_path: Path,
    state_path: Path,
    max_age_hours: int,
    strict_first_seen: bool,
    fail_on_empty: bool,
    xray_path: Path,
    source_concurrency: int = 32,
    analysis_workers: int = 120,
    analysis_batch_size: int = 1024,
    probe_timeout_seconds: float = 0.75,
    probe_startup_timeout_seconds: float = 1.0,
    probe_concurrency: int = 32,
    probe_batch_size: int = 256,
    probe_batch_concurrency: int = 2,
    tcp_precheck_timeout_seconds: float = 0.35,
    tcp_precheck_concurrency: int = 256,
    client: httpx.AsyncClient | None = None,
) -> int:
    """Collect, statically filter, Xray-validate, and publish supported profiles."""
    started_at = datetime.now(UTC)
    monotonic_started_at = perf_counter()
    stats = RunStats()
    sources = []
    logger.info("Конвейер сбора подписок: запуск.")
    if source_concurrency < 1:
        raise ValueError("source_concurrency must be positive")
    if analysis_workers < 1:
        raise ValueError("analysis_workers must be positive")
    if analysis_batch_size < 1:
        raise ValueError("analysis_batch_size must be positive")
    if probe_timeout_seconds <= 0:
        raise ValueError("probe_timeout_seconds must be positive")
    if probe_startup_timeout_seconds <= 0:
        raise ValueError("probe_startup_timeout_seconds must be positive")
    if probe_concurrency < 1:
        raise ValueError("probe_concurrency must be positive")
    if probe_batch_size < 1:
        raise ValueError("probe_batch_size must be positive")
    if probe_batch_concurrency < 1:
        raise ValueError("probe_batch_concurrency must be positive")
    if tcp_precheck_timeout_seconds <= 0:
        raise ValueError("tcp_precheck_timeout_seconds must be positive")
    if tcp_precheck_concurrency < 1:
        raise ValueError("tcp_precheck_concurrency must be positive")

    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Этап «Подготовка»: начат — проверка списка источников.")
    try:
        urls = read_input_urls(input_path)
    except InputError:
        logger.error(
            "Этап «Подготовка»: ошибка входного файла — разрешены только HTTPS-адреса "
            "без учётных данных; проверьте input.txt."
        )
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
    active_client = client or default_client(source_concurrency)
    try:
        sources = await fetch_sources(
            urls,
            active_client,
            started_at,
            max_age_hours,
            concurrency=source_concurrency,
        )
    finally:
        if owns_client:
            await active_client.aclose()
    fetch_duration_ms = _stage_duration_ms(stats, "sources_fetch", fetch_started_at)
    usable_sources = sum(source.text is not None for source in sources)
    logger.info(
        "Этап «Загрузка источников»: завершён за %s — пригодных источников: %d, "
        "исключённых: %d.",
        _duration_text(fetch_duration_ms),
        usable_sources,
        len(sources) - usable_sources,
    )

    static_filter_started_at = perf_counter()
    logger.info(
        "Этап «Статическая фильтрация»: начат — потоков: %d, размер батча: %d.",
        analysis_workers,
        analysis_batch_size,
    )
    accepted: list[Profile] = []
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=analysis_workers) as executor:
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
            for batch_start in range(0, len(lines), analysis_batch_size):
                line_batch = lines[batch_start : batch_start + analysis_batch_size]
                results = await asyncio.gather(
                    *(
                        loop.run_in_executor(
                            executor,
                            _parse_and_filter_candidate,
                            line,
                            source.source_url,
                        )
                        for line in line_batch
                    )
                )
                for profile, parsed, reason in results:
                    if not parsed:
                        stats.exclude(reason or "invalid_or_unsupported")
                        continue
                    stats.parsed_profiles += 1
                    if profile is None:
                        stats.exclude(reason or "policy_rejected")
                        continue
                    accepted.append(profile)
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

    tcp_precheck_started_at = perf_counter()
    logger.info(
        "Этап «TCP-предфильтр»: начат — профилей: %d, параллельность: %d.",
        len(unique),
        tcp_precheck_concurrency,
    )

    async def run_tcp_precheck(profile: Profile) -> str | None:
        return await tcp_precheck(profile, timeout_seconds=tcp_precheck_timeout_seconds)

    prechecked = await _filter_tcp_reachable_profiles(
        unique,
        runner=run_tcp_precheck,
        concurrency=tcp_precheck_concurrency,
        stats=stats,
    )
    tcp_precheck_duration_ms = _stage_duration_ms(stats, "tcp_precheck", tcp_precheck_started_at)
    logger.info(
        "Этап «TCP-предфильтр»: завершён за %s — допущено: %d, исключено: %d.",
        _duration_text(tcp_precheck_duration_ms),
        len(prechecked),
        len(unique) - len(prechecked),
    )

    validation_started_at = perf_counter()
    logger.info(
        "Этап «Xray IP-проверка»: начат — профилей: %d, параллельность: %d, размер батча: %d.",
        len(prechecked),
        probe_concurrency,
        probe_batch_size,
    )

    async def run_probe_batch(batch: Sequence[Profile]) -> list[ProbeResult]:
        return await probe_batch(
            batch,
            xray_path,
            timeout_seconds=probe_timeout_seconds,
            startup_timeout_seconds=probe_startup_timeout_seconds,
            request_concurrency=probe_concurrency,
        )

    validated = await _validate_profiles(
        prechecked,
        batch_runner=run_probe_batch,
        batch_concurrency=probe_batch_concurrency,
        batch_size=probe_batch_size,
        stats=stats,
    )
    validation_duration_ms = _stage_duration_ms(stats, "xray_ip_validation", validation_started_at)
    logger.info(
        "Этап «Xray IP-проверка»: завершён за %s — прошли: %d, исключены: %d.",
        _duration_text(validation_duration_ms),
        stats.validated_profiles,
        len(prechecked) - stats.validated_profiles,
    )

    publication_started_at = perf_counter()
    logger.info("Этап «Публикация»: начат.")
    fingerprints_by_profile_id = {
        id(profile): profile_fingerprint(profile) for profile in validated
    }
    state = update_state(state_path, list(fingerprints_by_profile_id.values()), started_at)
    profiles = list(validated)
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
    try:
        publication = publish_profiles(output_dir, profiles)
        stats.emitted_profiles = publication.new_profiles
        stats.published_new_by_protocol = publication.new_by_protocol
        stats.published_total_by_protocol = publication.total_by_protocol
        _stage_duration_ms(stats, "publication", publication_started_at)
        stats.timing_ms["total"] = round((perf_counter() - monotonic_started_at) * 1000)
        write_json_atomic(
            report_path,
            build_report(
                started_at=started_at,
                sources=sources,
                stats=stats,
                max_age_hours=max_age_hours,
                strict_first_seen=strict_first_seen,
            ),
        )
    except OSError:
        logger.error(
            "Этап «Публикация»: ошибка записи результата. "
            "Проверьте права доступа и свободное место."
        )
        raise
    logger.info(
        "Этап «Публикация»: завершён — добавлено профилей: %d. Конвейер завершён за %s.",
        publication.new_profiles,
        _duration_text(stats.timing_ms["total"]),
    )
    return 2 if fail_on_empty and publication.new_profiles == 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and Xray-validate secure VLESS, Trojan and Hysteria2 profiles"
    )
    parser.add_argument("--input", type=Path, default=Path("input.txt"))
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--report", type=Path, default=Path("report.json"))
    parser.add_argument("--state", type=Path, default=Path(".collector/state.json"))
    parser.add_argument("--max-age-hours", type=int, default=72)
    parser.add_argument("--strict-first-seen", action="store_true")
    parser.add_argument("--fail-on-empty", action="store_true")
    parser.add_argument("--xray-path", type=Path, required=True)
    parser.add_argument("--probe-timeout-seconds", type=float, default=0.75)
    parser.add_argument("--probe-startup-timeout-seconds", type=float, default=1.0)
    parser.add_argument("--probe-concurrency", type=int, default=32)
    parser.add_argument("--probe-batch-size", type=int, default=256)
    parser.add_argument("--probe-batch-concurrency", type=int, default=2)
    parser.add_argument("--tcp-precheck-timeout-seconds", type=float, default=0.35)
    parser.add_argument("--tcp-precheck-concurrency", type=int, default=256)
    parser.add_argument("--source-concurrency", type=int, default=32)
    parser.add_argument("--analysis-workers", type=int, default=120)
    parser.add_argument("--analysis-batch-size", type=int, default=1024)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    return asyncio.run(
        run_collection(
            input_path=args.input,
            output_dir=args.output_dir,
            report_path=args.report,
            state_path=args.state,
            max_age_hours=args.max_age_hours,
            strict_first_seen=args.strict_first_seen,
            fail_on_empty=args.fail_on_empty,
            xray_path=args.xray_path,
            probe_timeout_seconds=args.probe_timeout_seconds,
            probe_startup_timeout_seconds=args.probe_startup_timeout_seconds,
            probe_concurrency=args.probe_concurrency,
            probe_batch_size=args.probe_batch_size,
            probe_batch_concurrency=args.probe_batch_concurrency,
            tcp_precheck_timeout_seconds=args.tcp_precheck_timeout_seconds,
            tcp_precheck_concurrency=args.tcp_precheck_concurrency,
            source_concurrency=args.source_concurrency,
            analysis_workers=args.analysis_workers,
            analysis_batch_size=args.analysis_batch_size,
        )
    )
