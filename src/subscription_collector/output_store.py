"""Accumulating publication of validated profiles into protocol files.

Every run merges its freshly validated profiles into the durable pool and
rewrites the protocol files from the pool, so final files grow across runs up
to the configured per-protocol cap instead of holding only the current run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from .accumulation import (
    AccumulationReport,
    enforce_cap,
    load_pool,
    merge_profiles,
    render_lines,
    roll_cycle,
    save_pool,
)
from .config_loader import PublicationConfig
from .dedup import deduplicate, profile_fingerprint
from .models import Profile, Protocol
from .renamer import render_named_uri
from .writer import write_text_atomic

OUTPUT_FILENAMES: Mapping[Protocol, str] = {
    Protocol.VLESS: "vless.txt",
    Protocol.TROJAN: "trojan.txt",
    Protocol.HYSTERIA2: "hysteria2.txt",
}

# Imported for re-export so callers keep a single publication entry point.
__all__ = [
    "OUTPUT_FILENAMES",
    "AccumulationReport",
    "publish_profiles",
]


def _profiles_by_protocol(profiles: Iterable[Profile]) -> dict[Protocol, list[Profile]]:
    grouped = {protocol: [] for protocol in OUTPUT_FILENAMES}
    for profile in profiles:
        grouped[profile.protocol].append(profile)
    return grouped


def _cycle_position(now: datetime, cycle_started_at: str, cycle_days: int) -> tuple[int, int]:
    """Return ``(day_number, days_until_reset)`` for reporting."""
    try:
        started = datetime.fromisoformat(cycle_started_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 1, cycle_days
    age_days = max((now - started).days, 0)
    if age_days >= cycle_days:
        return cycle_days + 1, 0
    return age_days + 1, cycle_days - age_days


def publish_profiles(
    output_dir: Path,
    profiles: Iterable[Profile],
    *,
    pool_path: Path,
    settings: PublicationConfig | None = None,
    now: datetime | None = None,
) -> AccumulationReport:
    """Merge validated profiles into the pool and republish the protocol files.

    Existing entries are carried over untouched; new fingerprints are appended;
    duplicates only refresh their last-seen timestamp. The pool is capped per
    protocol and rolls over on the first run after ``cycle_days`` days.
    """
    effective_settings = settings or PublicationConfig()
    moment = now or datetime.now(UTC)
    output_dir.mkdir(parents=True, exist_ok=True)

    pool = load_pool(pool_path)
    reset_this_run = roll_cycle(pool, moment, effective_settings.cycle_days)

    added_by_protocol: dict[str, int] = {}
    refreshed_by_protocol: dict[str, int] = {}
    evicted_by_protocol: dict[str, int] = {}
    total_by_protocol: dict[str, int] = {}

    current_by_protocol = _profiles_by_protocol(profiles)
    for protocol, filename in OUTPUT_FILENAMES.items():
        entries = pool.entries(protocol.value)
        # roll_cycle already wiped the pool on a reset run, so anything present
        # here genuinely survived from earlier runs of the current cycle.
        current_unique = deduplicate(current_by_protocol[protocol])
        rendered = [
            (profile_fingerprint(profile), render_named_uri(profile, profile_fingerprint(profile)))
            for profile in current_unique
        ]
        added, refreshed = merge_profiles(pool, protocol.value, rendered, moment)
        evicted = enforce_cap(pool, protocol.value, effective_settings.max_profiles_per_protocol)
        added_by_protocol[protocol.value] = added
        refreshed_by_protocol[protocol.value] = refreshed
        evicted_by_protocol[protocol.value] = evicted
        total_by_protocol[protocol.value] = len(entries)
        write_text_atomic(
            output_dir / filename,
            "\n".join(render_lines(entries)) + ("\n" if entries else ""),
        )

    save_pool(pool_path, pool)
    cycle_day, days_until_reset = _cycle_position(
        moment, pool.cycle_started_at, effective_settings.cycle_days
    )
    return AccumulationReport(
        reset_this_run=reset_this_run,
        cycle_started_at=pool.cycle_started_at,
        cycle_day=cycle_day,
        days_until_reset=days_until_reset,
        cap_per_protocol=effective_settings.max_profiles_per_protocol,
        added_by_protocol=added_by_protocol,
        refreshed_by_protocol=refreshed_by_protocol,
        carried_by_protocol={
            protocol.value: (
                max(len(pool.entries(protocol.value)) - added_by_protocol[protocol.value], 0)
                if not reset_this_run
                else 0
            )
            for protocol in OUTPUT_FILENAMES
        },
        evicted_by_protocol=evicted_by_protocol,
        total_by_protocol=total_by_protocol,
    )
