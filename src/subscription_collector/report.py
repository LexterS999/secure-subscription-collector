from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from statistics import median

from .models import RunStats, SourceResult


def build_report(
    *,
    started_at: datetime,
    sources: Iterable[SourceResult],
    stats: RunStats,
    max_age_hours: int,
    strict_first_seen: bool,
    verification_enabled: bool,
) -> dict[str, object]:
    """Build a redacted audit record with aggregate source and validation outcomes only."""
    source_rows = [
        {
            "freshness": source.freshness.value,
            "last_modified": source.last_modified,
            "reason": source.reason,
        }
        for source in sources
    ]
    return {
        "generated_at": started_at.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "policy": "Strict Secure",
        "max_source_age_hours": max_age_hours,
        "strict_first_seen": strict_first_seen,
        "validation": {
            "enabled": verification_enabled,
            "probe_urls_per_profile": 4 if verification_enabled else 0,
            "required_successes": 2 if verification_enabled else 0,
            "median_latency_ms": (
                round(median(stats.validation_median_latencies_ms))
                if stats.validation_median_latencies_ms
                else None
            ),
        },
        "sources": source_rows,
        "timing_ms": dict(sorted(stats.timing_ms.items())),
        "counts": {
            "input_sources": stats.input_sources,
            "fetched_sources": stats.fetched_sources,
            "candidate_lines": stats.candidate_lines,
            "parsed_profiles": stats.parsed_profiles,
            "accepted_profiles": stats.accepted_profiles,
            "unique_profiles": stats.unique_profiles,
            "validation_attempted": stats.validation_attempted,
            "validation_passed": stats.validation_passed,
            "validation_failed": stats.validation_failed,
            "emitted_profiles": stats.emitted_profiles,
            "source_freshness": dict(sorted(stats.source_freshness.items())),
            "excluded": dict(sorted(stats.excluded.items())),
        },
    }
