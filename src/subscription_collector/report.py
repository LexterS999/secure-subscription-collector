from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from .models import RunStats, SourceResult

_PROTOCOLS = ("vless", "trojan", "hysteria2", "tuic")


def build_report(
    *,
    started_at: datetime,
    sources: Iterable[SourceResult],
    stats: RunStats,
    max_age_hours: int,
    strict_first_seen: bool,
) -> dict[str, object]:
    """Build a redacted audit record with aggregate source and publication outcomes."""
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
        "sources": source_rows,
        "timing_ms": dict(sorted(stats.timing_ms.items())),
        "publication": {
            "protocols": {
                protocol: {
                    "new": stats.published_new_by_protocol.get(protocol, 0),
                    "total": stats.published_total_by_protocol.get(protocol, 0),
                }
                for protocol in _PROTOCOLS
            }
        },
        "counts": {
            "input_sources": stats.input_sources,
            "fetched_sources": stats.fetched_sources,
            "candidate_lines": stats.candidate_lines,
            "parsed_profiles": stats.parsed_profiles,
            "accepted_profiles": stats.accepted_profiles,
            "unique_profiles": stats.unique_profiles,
            "emitted_profiles": stats.emitted_profiles,
            "source_freshness": dict(sorted(stats.source_freshness.items())),
            "excluded": dict(sorted(stats.excluded.items())),
        },
    }
