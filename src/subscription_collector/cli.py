from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import httpx

from .channel_quality import ChannelEvaluation, ChannelMetrics, evaluate_channel
from .channel_state import (
    channel_state_key,
    load_channel_state,
    update_channel_state,
    write_channel_registry,
)
from .config_loader import (
    CollectorConfig,
    ConfigError,
    TelegramConfig,
    load_config,
    validate_config,
)
from .decoder import extract_candidate_lines
from .dedup import deduplicate, profile_fingerprint
from .fetcher import default_client, fetch_sources, fetch_telegram_previews
from .input_reader import InputError, read_input_urls
from .models import ProbeResult, Profile, RunStats, SourceResult, TelegramPost
from .output_store import publish_profiles
from .parser import parse_profile
from .policy import evaluate_strict_secure
from .probe import probe_batch
from .report import build_report
from .state import update_state
from .telegram import (
    canonical_preview_url,
    channel_reference_handle,
    extract_candidate_profile_uris,
    extract_profile_uris,
    extract_telegram_handles,
    parse_preview_posts,
)
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
    if channel_reference_handle(line) is not None:
        return None, True, "telegram_channel_reference"
    profile = parse_profile(line, source_url)
    if profile is None:
        return None, False, "invalid_or_unsupported"
    decision = evaluate_strict_secure(profile)
    if decision.profile is None:
        return None, True, decision.reason or "policy_rejected"
    return decision.profile, True, None


@dataclass(frozen=True, slots=True)
class _TelegramObservation:
    """Aggregated per-channel preview outcome kept separate from shared statistics."""

    handle: str
    posts: list[TelegramPost]
    supported_uris: list[str]
    static_accepted: list[Profile]
    unique_profiles: list[Profile]
    preview_available: bool


def _parse_telegram_posts(
    handles: Sequence[str],
    previews: Sequence[SourceResult],
    now: datetime,
    settings: TelegramConfig,
) -> dict[str, list[TelegramPost]]:
    posts_by_handle: dict[str, list[TelegramPost]] = {}
    for handle, preview in zip(handles, previews, strict=True):
        if preview.text is None:
            posts_by_handle[handle] = []
            continue
        posts_by_handle[handle] = parse_preview_posts(
            preview.text, handle, now, settings.max_post_age_hours
        )
    return posts_by_handle


def _channel_metrics(
    posts: list[TelegramPost], observation: _TelegramObservation
) -> ChannelMetrics:
    seen_texts: set[str] = set()
    duplicate_posts = 0
    for post in posts:
        if post.text in seen_texts:
            duplicate_posts += 1
        else:
            seen_texts.add(post.text)
    span_hours = 0.0
    if posts:
        published = [
            datetime.fromisoformat(post.published_at.replace("Z", "+00:00")) for post in posts
        ]
        span_hours = (max(published) - min(published)).total_seconds() / 3600
    return ChannelMetrics(
        preview_available=observation.preview_available,
        fresh_posts=len(posts),
        all_uri_candidates=len(extract_candidate_profile_uris(posts)),
        supported_candidates=len(observation.supported_uris),
        static_accepted=len(observation.static_accepted),
        unique_profiles=len(observation.unique_profiles),
        duplicate_posts=duplicate_posts,
        posts_with_profiles=sum(1 for post in posts if extract_profile_uris([post])),
        total_text_length=sum(len(post.text) for post in posts),
        span_hours=span_hours,
    )


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
        profiles[start : start + batch_size] for start in range(0, len(profiles), batch_size)
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
    *, config: CollectorConfig, client: httpx.AsyncClient | None = None
) -> int:
    """Collect, statically filter, Xray-validate, and publish supported profiles."""
    started_at = datetime.now(UTC)
    monotonic_started_at = perf_counter()
    stats = RunStats()
    sources = []
    paths = config.paths
    source_settings = config.sources
    filter_settings = config.static_filter
    validation_settings = config.ip_validation
    behavior = config.behavior
    telegram_settings = config.telegram

    logger.info("Конвейер сбора подписок: запуск.")
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Этап «Подготовка»: начат — проверка списка источников.")
    try:
        urls = read_input_urls(paths.input_path)
    except InputError:
        logger.error(
            "Этап «Подготовка»: ошибка входного файла — разрешены только HTTPS-адреса "
            "без учётных данных; проверьте input.txt."
        )
        write_json_atomic(
            paths.report_path,
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
    active_client = client or default_client(source_settings)
    discovered_handles: list[str] = []
    preview_results: list[SourceResult] = []
    try:
        sources = await fetch_sources(urls, active_client, started_at, source_settings)
        for source in sources:
            if source.text is None:
                continue
            for handle in sorted(extract_telegram_handles(source.text)):
                if handle not in discovered_handles:
                    discovered_handles.append(handle)
        discovered_handles.sort()
        write_channel_registry(paths.tg_channels_path, discovered_handles)
        write_channel_registry(paths.telegram_registry_path, discovered_handles)
        if discovered_handles:
            preview_results = await fetch_telegram_previews(
                discovered_handles, active_client, started_at, telegram_settings
            )
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

    telegram_posts_by_handle = _parse_telegram_posts(
        discovered_handles, preview_results, started_at, telegram_settings
    )
    telegram_posts = [
        post for posts in telegram_posts_by_handle.values() for post in posts
    ]
    if discovered_handles:
        logger.info(
            "Telegram: обнаружено публичных каналов: %d; свежих сообщений: %d; URI-кандидатов: %d.",
            len(discovered_handles),
            len(telegram_posts),
            len(extract_profile_uris(telegram_posts)),
        )

    static_filter_started_at = perf_counter()
    logger.info(
        "Этап «Статическая фильтрация»: начат — потоков: %d, размер батча: %d.",
        filter_settings.workers,
        filter_settings.batch_size,
    )
    accepted: list[Profile] = []
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=filter_settings.workers) as executor:
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
            for batch_start in range(0, len(lines), filter_settings.batch_size):
                line_batch = lines[batch_start : batch_start + filter_settings.batch_size]
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

    observations: dict[str, _TelegramObservation] = {}
    for handle, posts in telegram_posts_by_handle.items():
        preview_url = canonical_preview_url(handle)
        supported_uris = extract_profile_uris(posts)
        channel_profiles: list[Profile] = []
        for uri in supported_uris:
            profile = parse_profile(uri, preview_url)
            if profile is None:
                continue
            decision = evaluate_strict_secure(profile)
            if decision.profile is not None:
                channel_profiles.append(decision.profile)
        if telegram_settings.max_profiles_per_channel is not None:
            channel_profiles = channel_profiles[: telegram_settings.max_profiles_per_channel]
        observation = _TelegramObservation(
            handle=handle,
            posts=posts,
            supported_uris=supported_uris,
            static_accepted=channel_profiles,
            unique_profiles=deduplicate(channel_profiles),
            preview_available=any(
                result.source_url == preview_url and result.text is not None
                for result in preview_results
            ),
        )
        observations[handle] = observation
        accepted.extend(observation.static_accepted)

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

    validation_started_at = perf_counter()
    excluded_before_validation = stats.excluded.copy()
    logger.info(
        "Этап «Xray IP-проверка»: начат — профилей: %d, параллельность: %d, размер батча: %d.",
        len(unique),
        validation_settings.request_concurrency,
        validation_settings.batch_size,
    )

    async def run_probe_batch(batch: Sequence[Profile]) -> list[ProbeResult]:
        return await probe_batch(batch, paths.xray_path, settings=validation_settings)

    validated = await _validate_profiles(
        unique,
        batch_runner=run_probe_batch,
        batch_concurrency=validation_settings.batch_concurrency,
        batch_size=validation_settings.batch_size,
        stats=stats,
    )
    validation_duration_ms = _stage_duration_ms(stats, "xray_ip_validation", validation_started_at)
    logger.info(
        "Этап «Xray IP-проверка»: завершён за %s — прошли: %d, исключены: %d.",
        _duration_text(validation_duration_ms),
        stats.validated_profiles,
        len(unique) - stats.validated_profiles,
    )
    validation_failures = {
        reason: count - excluded_before_validation.get(reason, 0)
        for reason, count in stats.excluded.items()
        if count > excluded_before_validation.get(reason, 0)
    }
    if validation_failures:
        summary = ", ".join(
            f"{reason}: {count}" for reason, count in sorted(validation_failures.items())
        )
        logger.info("Причины отказов Xray IP-проверки: %s.", summary)

    handle_by_preview_url = {
        canonical_preview_url(handle): handle for handle in discovered_handles
    }
    xray_probed_by_handle = dict.fromkeys(discovered_handles, 0)
    xray_passed_by_handle = dict.fromkeys(discovered_handles, 0)
    for profile in unique:
        handle = handle_by_preview_url.get(profile.source_url)
        if handle is not None:
            xray_probed_by_handle[handle] += 1
    for profile in validated:
        handle = handle_by_preview_url.get(profile.source_url)
        if handle is not None:
            xray_passed_by_handle[handle] += 1
    telegram_xray_passed = sum(xray_passed_by_handle.values())

    channel_evaluations: dict[str, ChannelEvaluation] = {}
    if discovered_handles:
        previous_channels = load_channel_state(paths.telegram_state_path)
        for handle in discovered_handles:
            observation = observations[handle]
            metrics = _channel_metrics(observation.posts, observation)
            metrics = replace(
                metrics,
                xray_passed=xray_passed_by_handle[handle],
                xray_failed=xray_probed_by_handle[handle] - xray_passed_by_handle[handle],
            )
            previous = previous_channels.get(channel_state_key(handle))
            channel_evaluations[handle] = evaluate_channel(
                handle,
                metrics,
                previous,
                telegram_settings.quality,
                started_at,
            )
        update_channel_state(paths.telegram_state_path, channel_evaluations, started_at)
    approved_channels = sum(
        1 for evaluation in channel_evaluations.values() if evaluation.status == "approved"
    )

    publication_started_at = perf_counter()
    logger.info("Этап «Публикация»: начат.")
    fingerprints_by_profile_id = {
        id(profile): profile_fingerprint(profile) for profile in validated
    }
    state = update_state(paths.state_path, list(fingerprints_by_profile_id.values()), started_at)
    profiles = list(validated)
    if behavior.strict_first_seen:
        profiles = [
            profile
            for profile in profiles
            if _within_first_seen_window(
                state[fingerprints_by_profile_id[id(profile)]].first_seen_at,
                started_at,
                source_settings.max_age_hours,
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
        publication = publish_profiles(paths.output_dir, profiles)
        stats.emitted_profiles = publication.new_profiles
        stats.published_new_by_protocol = publication.new_by_protocol
        stats.published_total_by_protocol = publication.total_by_protocol
        _stage_duration_ms(stats, "publication", publication_started_at)
        stats.timing_ms["total"] = round((perf_counter() - monotonic_started_at) * 1000)
        write_json_atomic(
            paths.report_path,
            build_report(
                started_at=started_at,
                sources=sources,
                stats=stats,
                max_age_hours=source_settings.max_age_hours,
                strict_first_seen=behavior.strict_first_seen,
                telegram={
                    "discovered_channels": len(discovered_handles),
                    "approved_channels": approved_channels,
                    "uri_candidates": sum(
                        len(observation.supported_uris) for observation in observations.values()
                    ),
                    "static_accepted_profiles": sum(
                        len(observation.static_accepted) for observation in observations.values()
                    ),
                    "unique_profiles": sum(
                        len(observation.unique_profiles) for observation in observations.values()
                    ),
                    "xray_passed_profiles": telegram_xray_passed,
                },
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
    return 2 if behavior.fail_on_empty and publication.new_profiles == 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and Xray-validate secure VLESS, Trojan and Hysteria2 profiles"
    )
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--max-age-hours", type=int)
    parser.add_argument("--strict-first-seen", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--fail-on-empty", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--xray-path", type=Path)
    parser.add_argument("--probe-timeout-seconds", type=float)
    parser.add_argument("--probe-startup-timeout-seconds", type=float)
    parser.add_argument("--probe-concurrency", type=int)
    parser.add_argument("--probe-batch-size", type=int)
    parser.add_argument("--probe-batch-concurrency", type=int)
    parser.add_argument("--probe-listener-poll-interval-seconds", type=float)
    parser.add_argument("--probe-process-shutdown-timeout-seconds", type=float)
    parser.add_argument("--probe-connection-max-connections", type=int)
    parser.add_argument("--probe-connection-max-keepalive-connections", type=int)
    parser.add_argument("--source-concurrency", type=int)
    parser.add_argument("--source-timeout-seconds", type=float)
    parser.add_argument("--source-max-response-bytes", type=int)
    parser.add_argument("--source-max-redirects", type=int)
    parser.add_argument("--source-user-agent")
    parser.add_argument("--analysis-workers", type=int)
    parser.add_argument("--analysis-batch-size", type=int)
    return parser


def _apply_cli_overrides(config: CollectorConfig, args: argparse.Namespace) -> CollectorConfig:
    return replace(
        config,
        paths=replace(
            config.paths,
            input_path=args.input or config.paths.input_path,
            output_dir=args.output_dir or config.paths.output_dir,
            report_path=args.report or config.paths.report_path,
            state_path=args.state or config.paths.state_path,
            xray_path=args.xray_path or config.paths.xray_path,
        ),
        sources=replace(
            config.sources,
            max_age_hours=args.max_age_hours or config.sources.max_age_hours,
            concurrency=args.source_concurrency or config.sources.concurrency,
            timeout_seconds=args.source_timeout_seconds or config.sources.timeout_seconds,
            max_response_bytes=args.source_max_response_bytes or config.sources.max_response_bytes,
            max_redirects=(
                args.source_max_redirects
                if args.source_max_redirects is not None
                else config.sources.max_redirects
            ),
            user_agent=args.source_user_agent or config.sources.user_agent,
        ),
        static_filter=replace(
            config.static_filter,
            workers=args.analysis_workers or config.static_filter.workers,
            batch_size=args.analysis_batch_size or config.static_filter.batch_size,
        ),
        ip_validation=replace(
            config.ip_validation,
            timeout_seconds=args.probe_timeout_seconds or config.ip_validation.timeout_seconds,
            startup_timeout_seconds=(
                args.probe_startup_timeout_seconds or config.ip_validation.startup_timeout_seconds
            ),
            request_concurrency=args.probe_concurrency or config.ip_validation.request_concurrency,
            batch_size=args.probe_batch_size or config.ip_validation.batch_size,
            batch_concurrency=(
                args.probe_batch_concurrency or config.ip_validation.batch_concurrency
            ),
            listener_poll_interval_seconds=(
                args.probe_listener_poll_interval_seconds
                or config.ip_validation.listener_poll_interval_seconds
            ),
            process_shutdown_timeout_seconds=(
                args.probe_process_shutdown_timeout_seconds
                or config.ip_validation.process_shutdown_timeout_seconds
            ),
            connection_max_connections=(
                args.probe_connection_max_connections
                or config.ip_validation.connection_max_connections
            ),
            connection_max_keepalive_connections=(
                args.probe_connection_max_keepalive_connections
                if args.probe_connection_max_keepalive_connections is not None
                else config.ip_validation.connection_max_keepalive_connections
            ),
        ),
        behavior=replace(
            config.behavior,
            strict_first_seen=(
                args.strict_first_seen
                if args.strict_first_seen is not None
                else config.behavior.strict_first_seen
            ),
            fail_on_empty=(
                args.fail_on_empty
                if args.fail_on_empty is not None
                else config.behavior.fail_on_empty
            ),
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = validate_config(_apply_cli_overrides(load_config(args.config), args))
    except ConfigError as exc:
        parser.error(str(exc))
    return asyncio.run(run_collection(config=config))
