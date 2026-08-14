from __future__ import annotations

import argparse
import asyncio
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

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


def _within_first_seen_window(first_seen_at: str, now: datetime, hours: int) -> bool:
    parsed = datetime.fromisoformat(first_seen_at.replace("Z", "+00:00"))
    return parsed >= now.astimezone(UTC) - timedelta(hours=hours)


async def _validate_profiles(
    profiles: list[Profile],
    *,
    runner: ProbeRunner,
    concurrency: int,
    stats: RunStats,
) -> list[Profile]:
    semaphore = asyncio.Semaphore(concurrency)

    async def validate_one(profile: Profile) -> tuple[Profile, ProbeResult]:
        async with semaphore:
            return profile, await runner(profile)

    results = await asyncio.gather(*(validate_one(profile) for profile in profiles))
    accepted: list[Profile] = []
    for profile, result in results:
        stats.validation_attempted += 1
        if result.passed:
            stats.validation_passed += 1
            if result.median_latency_ms is not None:
                stats.validation_median_latencies_ms.append(result.median_latency_ms)
            accepted.append(profile)
        else:
            stats.validation_failed += 1
            stats.exclude(f"validation:{result.error_category or 'quorum'}")
    return accepted


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
    probe_timeout_seconds: float = 10.0,
    probe_concurrency: int = 4,
    probe_runner: ProbeRunner | None = None,
) -> int:
    """Collect, statically filter, URL-test and publish profiles without logging profile secrets."""
    started_at = datetime.now(UTC)
    stats = RunStats()
    sources = []
    if probe_concurrency < 1:
        raise ValueError("probe_concurrency must be positive")
    if verify_profiles and probe_runner is None and sing_box_path is None:
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
    try:
        urls = read_input_urls(input_path)
    except InputError:
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

    stats.input_sources = len(urls)
    owns_client = client is None
    active_client = client or default_client()
    try:
        sources = await fetch_sources(urls, active_client, started_at, max_age_hours)
    finally:
        if owns_client:
            await active_client.aclose()

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

    unique = deduplicate(accepted)
    stats.unique_profiles = len(unique)
    if verify_profiles:
        if probe_runner is None:
            assert sing_box_path is not None

            async def probe_runner(profile: Profile) -> ProbeResult:
                return await probe_profile(
                    profile,
                    sing_box_path,
                    timeout_seconds=probe_timeout_seconds,
                )

        unique = await _validate_profiles(
            unique,
            runner=probe_runner,
            concurrency=probe_concurrency,
            stats=stats,
        )

    fingerprints = {profile_fingerprint(profile): profile for profile in unique}
    state = update_state(state_path, list(fingerprints), started_at)
    profiles = list(fingerprints.values())
    if strict_first_seen:
        profiles = [
            profile
            for profile in profiles
            if _within_first_seen_window(
                state[profile_fingerprint(profile)].first_seen_at,
                started_at,
                max_age_hours,
            )
        ]
    profiles.sort(
        key=lambda item: (
            item.protocol.value,
            item.security,
            item.transport,
            profile_fingerprint(item),
        )
    )
    output_lines = [render_named_uri(profile, profile_fingerprint(profile)) for profile in profiles]
    write_text_atomic(output_path, "\n".join(output_lines) + ("\n" if output_lines else ""))
    stats.emitted_profiles = len(output_lines)
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
    parser.add_argument("--probe-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--probe-concurrency", type=int, default=4)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
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
            probe_concurrency=args.probe_concurrency,
        )
    )
