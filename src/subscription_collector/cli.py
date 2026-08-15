from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import httpx

from .channel_quality import ChannelMetrics, evaluate_channel
from .channel_state import (
    channel_state_key,
    load_channel_state,
    update_channel_state,
    write_channel_registry,
)
from .config_loader import CollectorConfig, ConfigError, load_config, validate_config
from .decoder import extract_candidate_lines
from .dedup import deduplicate, profile_fingerprint
from .fetcher import (
    default_client,
    fetch_sources,
    fetch_telegram_preview_page,
    fetch_telegram_previews,
)
from .input_reader import InputError, read_input_urls
from .models import ProbeResult, Profile, RunStats
from .output_store import publish_profiles
from .parser import parse_profile
from .policy import evaluate_strict_secure
from .probe import probe_batch
from .report import build_report
from .state import update_state
from .telegram import extract_profile_uris, extract_telegram_handles, parse_preview_posts
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
    """Apply URI parsing and strict policy without mutating shared statistics."""
    profile = parse_profile(line, source_url)
    if profile is None:
        return None, False, "invalid_or_unsupported"
    decision = evaluate_strict_secure(profile)
    if decision.profile is None:
        return None, True, decision.reason or "policy_rejected"
    return decision.profile, True, None


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


def _parse_channel_profiles(
    raw_uris: Sequence[str],
    source_url: str,
    stats: RunStats,
) -> tuple[list[Profile], int, int]:
    """Apply existing URI parser and policy to one channel without retaining raw URI externally."""
    static_profiles: list[Profile] = []
    supported_candidates = 0
    static_accepted = 0
    for raw_uri in raw_uris:
        stats.candidate_lines += 1
        profile, parsed, reason = _parse_and_filter_candidate(raw_uri, source_url)
        if not parsed:
            stats.exclude(reason or "invalid_or_unsupported")
            continue
        supported_candidates += 1
        stats.parsed_profiles += 1
        if profile is None:
            stats.exclude(reason or "policy_rejected")
            continue
        static_profiles.append(profile)
        static_accepted += 1
        stats.accepted_profiles += 1
    return deduplicate(static_profiles), supported_candidates, static_accepted


async def run_collection(
    *, config: CollectorConfig, client: httpx.AsyncClient | None = None
) -> int:
    """Discover public channels from seeds and publish only quality-gated Xray profiles."""
    started_at = datetime.now(UTC)
    monotonic_started_at = perf_counter()
    stats = RunStats()
    paths = config.paths
    source_settings = config.sources
    telegram_settings = config.telegram
    validation_settings = config.ip_validation
    behavior = config.behavior

    logger.info("Конвейер Telegram-профилей: запуск.")
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Этап «Подготовка»: начат — проверка seed-источников.")
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
    logger.info("Этап «Подготовка»: завершён — seed-источников: %d.", len(urls))

    stats.input_sources = len(urls)
    owns_client = client is None
    active_client = client or default_client(source_settings)
    try:
        fetch_started_at = perf_counter()
        logger.info("Этап «Загрузка seed-источников»: начат — адресов: %d.", len(urls))
        sources = await fetch_sources(urls, active_client, started_at, source_settings)
        fetch_duration_ms = _stage_duration_ms(stats, "sources_fetch", fetch_started_at)
        usable_sources = sum(source.text is not None for source in sources)
        logger.info(
            "Этап «Загрузка seed-источников»: завершён за %s — пригодных: %d, исключённых: %d.",
            _duration_text(fetch_duration_ms),
            usable_sources,
            len(sources) - usable_sources,
        )

        discovery_started_at = perf_counter()
        discovered_handles: set[str] = set()
        for source in sources:
            stats.source_freshness[source.freshness.value] = (
                stats.source_freshness.get(source.freshness.value, 0) + 1
            )
            if source.text is None:
                stats.exclude(source.reason or source.freshness.value)
                continue
            stats.fetched_sources += 1
            seed_lines = extract_candidate_lines(source.text)
            stats.candidate_lines += len(seed_lines)
            for line in seed_lines:
                discovered_handles.update(extract_telegram_handles(line))
        write_channel_registry(telegram_settings.registry_path, discovered_handles)
        stats.telegram_discovered_channels = len(discovered_handles)
        _stage_duration_ms(stats, "telegram_discovery", discovery_started_at)
        logger.info("Этап «Discovery Telegram»: обнаружено каналов: %d.", len(discovered_handles))

        channel_state = load_channel_state(telegram_settings.state_path)
        active_handles = [
            handle
            for handle in sorted(discovered_handles)
            if channel_state.get(channel_state_key(handle), None) is None
            or channel_state[channel_state_key(handle)].status != "excluded"
        ]
        preview_started_at = perf_counter()
        previews = await fetch_telegram_previews(
            active_handles,
            active_client,
            started_at,
            telegram_settings,
        )
        _stage_duration_ms(stats, "telegram_preview_fetch", preview_started_at)
    finally:
        if owns_client:
            await active_client.aclose()

    async def fetch_next_preview(handle: str, before: str):
        if not owns_client:
            return await fetch_telegram_preview_page(
                handle,
                before,
                active_client,
                telegram_settings,
            )
        async with default_client(source_settings) as page_client:
            return await fetch_telegram_preview_page(
                handle,
                before,
                page_client,
                telegram_settings,
            )

    channel_profiles: dict[str, list[Profile]] = {}
    channel_sources: dict[str, str] = {}
    channel_metrics: dict[str, dict[str, int | bool]] = {}
    for handle, preview in zip(active_handles, previews, strict=True):
        channel_sources[handle] = preview.source_url
        metric_values: dict[str, int | bool] = {
            "preview_available": preview.text is not None,
            "fresh_posts": 0,
            "all_uri_candidates": 0,
            "supported_candidates": 0,
            "static_accepted": 0,
            "unique_profiles": 0,
        }
        if preview.text is None:
            stats.telegram_preview_failed += 1
            stats.exclude(preview.reason or "telegram_preview_failed")
            channel_profiles[handle] = []
            channel_metrics[handle] = metric_values
            continue
        posts = parse_preview_posts(
            preview.text,
            handle,
            started_at,
            telegram_settings.max_post_age_hours,
        )
        previous = channel_state.get(channel_state_key(handle))
        if previous is None or previous.status != "approved":
            posts = posts[: telegram_settings.sample_post_limit]
        else:
            seen_message_ids = {post.message_id for post in posts}
            before = posts[-1].message_id if posts else None
            for _ in range(1, telegram_settings.max_pages_per_channel):
                if before is None:
                    break
                next_preview = await fetch_next_preview(handle, before)
                if next_preview.text is None:
                    stats.exclude(next_preview.reason or "telegram_preview_failed")
                    break
                next_posts = parse_preview_posts(
                    next_preview.text,
                    handle,
                    started_at,
                    telegram_settings.max_post_age_hours,
                )
                if not next_posts:
                    break
                new_posts = [post for post in next_posts if post.message_id not in seen_message_ids]
                next_before = next_posts[-1].message_id
                if not new_posts or next_before == before:
                    break
                posts.extend(new_posts)
                seen_message_ids.update(post.message_id for post in new_posts)
                before = next_before
        raw_uris = extract_profile_uris(posts)
        stats.telegram_posts_in_window += len(posts)
        stats.telegram_uri_candidates += len(raw_uris)
        profiles, supported_candidates, static_accepted = _parse_channel_profiles(
            raw_uris,
            preview.source_url,
            stats,
        )
        metric_values.update(
            fresh_posts=len(posts),
            all_uri_candidates=len(raw_uris),
            supported_candidates=supported_candidates,
            static_accepted=static_accepted,
            unique_profiles=len(profiles),
        )
        stats.telegram_supported_uri += supported_candidates
        stats.telegram_policy_accepted_uri += static_accepted
        stats.telegram_unique_uri += len(profiles)
        channel_profiles[handle] = profiles
        channel_metrics[handle] = metric_values

    deduplication_started_at = perf_counter()
    all_profiles = [profile for profiles in channel_profiles.values() for profile in profiles]
    unique = deduplicate(all_profiles)
    stats.unique_profiles = len(unique)
    _stage_duration_ms(stats, "deduplication", deduplication_started_at)

    validation_started_at = perf_counter()
    excluded_before_validation = stats.excluded.copy()
    logger.info("Этап «Xray IP-проверка»: начат — профилей: %d.", len(unique))

    async def run_probe_batch(batch: Sequence[Profile]) -> list[ProbeResult]:
        return await probe_batch(batch, paths.xray_path, settings=validation_settings)

    validated = await _validate_profiles(
        unique,
        batch_runner=run_probe_batch,
        batch_concurrency=validation_settings.batch_concurrency,
        batch_size=validation_settings.batch_size,
        stats=stats,
    )
    _stage_duration_ms(stats, "xray_ip_validation", validation_started_at)
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
    validated_fingerprints = {profile_fingerprint(profile) for profile in validated}

    evaluation_started_at = perf_counter()
    evaluations = {}
    for handle in active_handles:
        local_profiles = channel_profiles[handle]
        xray_passed = sum(
            profile_fingerprint(profile) in validated_fingerprints for profile in local_profiles
        )
        metrics = channel_metrics[handle]
        evaluation = evaluate_channel(
            handle,
            ChannelMetrics(
                preview_available=bool(metrics["preview_available"]),
                fresh_posts=int(metrics["fresh_posts"]),
                all_uri_candidates=int(metrics["all_uri_candidates"]),
                supported_candidates=int(metrics["supported_candidates"]),
                static_accepted=int(metrics["static_accepted"]),
                unique_profiles=int(metrics["unique_profiles"]),
                xray_passed=xray_passed,
                xray_failed=len(local_profiles) - xray_passed,
            ),
            channel_state.get(channel_state_key(handle)),
            config.channel_quality,
            started_at,
        )
        evaluations[handle] = evaluation
    updated_channel_state = update_channel_state(
        telegram_settings.state_path,
        evaluations,
        started_at,
    )
    _stage_duration_ms(stats, "channel_quality", evaluation_started_at)
    discovered_records = [
        updated_channel_state.get(channel_state_key(handle)) for handle in discovered_handles
    ]
    stats.telegram_candidate_channels = sum(
        record is not None and record.status == "candidate" for record in discovered_records
    )
    stats.telegram_approved_channels = sum(
        record is not None and record.status == "approved" for record in discovered_records
    )
    stats.telegram_excluded_channels = sum(
        record is not None and record.status == "excluded" for record in discovered_records
    )

    approved_handles = {
        handle
        for handle, evaluation in evaluations.items()
        if evaluation.status == "approved"
    }
    approved_source_urls = {channel_sources[handle] for handle in approved_handles}
    profiles = [profile for profile in validated if profile.source_url in approved_source_urls]

    publication_started_at = perf_counter()
    fingerprints_by_profile_id = {id(profile): profile_fingerprint(profile) for profile in profiles}
    profile_state = update_state(
        paths.state_path,
        list(fingerprints_by_profile_id.values()),
        started_at,
    )
    if behavior.strict_first_seen:
        profiles = [
            profile
            for profile in profiles
            if _within_first_seen_window(
                profile_state[fingerprints_by_profile_id[id(profile)]].first_seen_at,
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
            ),
        )
    except OSError:
        logger.error(
            "Этап «Публикация»: ошибка записи результата. "
            "Проверьте права доступа и свободное место."
        )
        raise
    logger.info(
        "Этап «Публикация»: завершён — добавлено профилей: %d; каналов approved: %d; "
        "состояний: %d.",
        publication.new_profiles,
        len(approved_handles),
        len(updated_channel_state),
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
