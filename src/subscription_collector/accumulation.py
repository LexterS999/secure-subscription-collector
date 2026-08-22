"""Cross-run profile accumulation with a rolling publication cycle.

The final protocol files must grow between collection runs instead of being
replaced by the current run only. This module owns the durable profile pool:

* every validated profile is stored once per protocol, keyed by its stable
  fingerprint together with the rendered Android-client URI;
* repeated sightings refresh ``last_seen_at`` instead of duplicating the entry;
* the pool is capped per protocol; when the cap is exceeded the oldest entries
  (by last sighting) are evicted first;
* accumulation runs for ``cycle_days`` days (six by default). On the first run
  of day seven the pool is reset to zero and a new cycle starts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .writer import write_json_atomic

_POOL_SCHEMA = 1
_EPOCH_START = "1970-01-01T00:00:00Z"


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


@dataclass(slots=True)
class PoolEntry:
    """One accumulated profile: its rendered URI plus lifecycle timestamps."""

    uri: str
    first_added_at: str
    last_seen_at: str
    hits: int = 1


@dataclass(slots=True)
class ProfilePool:
    """Durable pool of accumulated profiles grouped by protocol."""

    cycle_started_at: str = _EPOCH_START
    generation: int = 1
    protocols: dict[str, dict[str, PoolEntry]] = field(
        default_factory=lambda: {"vless": {}, "trojan": {}, "hysteria2": {}}
    )

    def entries(self, protocol: str) -> dict[str, PoolEntry]:
        return self.protocols.setdefault(protocol, {})

    def total(self) -> int:
        return sum(len(entries) for entries in self.protocols.values())


def load_pool(path: Path) -> ProfilePool:
    """Load the pool from disk; a missing or corrupt file yields a fresh pool."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ProfilePool()
    if not isinstance(payload, dict) or payload.get("schema") != _POOL_SCHEMA:
        return ProfilePool()
    started_at = payload.get("cycle_started_at")
    generation = payload.get("generation")
    raw_protocols = payload.get("protocols")
    pool = ProfilePool(
        cycle_started_at=started_at if isinstance(started_at, str) else _EPOCH_START,
        generation=generation if isinstance(generation, int) and generation >= 1 else 1,
    )
    if not isinstance(raw_protocols, dict):
        return pool
    for protocol, raw_entries in raw_protocols.items():
        if not isinstance(protocol, str) or not isinstance(raw_entries, dict):
            continue
        entries = pool.entries(protocol)
        for fingerprint, raw_entry in raw_entries.items():
            if not isinstance(fingerprint, str) or len(fingerprint) != 64:
                continue
            if not isinstance(raw_entry, dict):
                continue
            uri = raw_entry.get("uri")
            first_added = raw_entry.get("first_added_at")
            last_seen = raw_entry.get("last_seen_at")
            hits = raw_entry.get("hits", 1)
            if not all(isinstance(value, str) and value for value in (uri, first_added, last_seen)):
                continue
            if not isinstance(hits, int) or hits < 1:
                hits = 1
            entries[fingerprint] = PoolEntry(
                uri=uri, first_added_at=first_added, last_seen_at=last_seen, hits=hits
            )
    return pool


def save_pool(path: Path, pool: ProfilePool) -> None:
    """Persist the pool atomically in a deterministic key order."""
    write_json_atomic(
        path,
        {
            "schema": _POOL_SCHEMA,
            "cycle_started_at": pool.cycle_started_at,
            "generation": pool.generation,
            "protocols": {
                protocol: {
                    fingerprint: {
                        "uri": entry.uri,
                        "first_added_at": entry.first_added_at,
                        "last_seen_at": entry.last_seen_at,
                        "hits": entry.hits,
                    }
                    for fingerprint, entry in sorted(entries.items())
                }
                for protocol, entries in sorted(pool.protocols.items())
            },
        },
    )


def roll_cycle(pool: ProfilePool, now: datetime, cycle_days: int) -> bool:
    """Reset the pool on the first run of day ``cycle_days + 1``.

    Returns ``True`` when a reset happened so callers can log and report it.
    A brand-new pool (epoch start, nothing accumulated yet) is anchored to the
    current run instead: the first publication begins cycle one rather than
    reporting a reset that discarded nothing. An unparseable cycle start is
    treated as long expired, which self-heals a damaged state file into a
    clean new cycle.
    """
    if pool.cycle_started_at == _EPOCH_START and pool.total() == 0 and pool.generation == 1:
        pool.cycle_started_at = _utc_timestamp(now)
        return False
    started = _parse_timestamp(pool.cycle_started_at)
    age_days = (now - started).days if started is not None else cycle_days
    if age_days < cycle_days:
        return False
    pool.protocols = {protocol: {} for protocol in pool.protocols}
    pool.cycle_started_at = _utc_timestamp(now)
    pool.generation += 1
    return True


def merge_profiles(
    pool: ProfilePool,
    protocol: str,
    rendered: Iterable[tuple[str, str]],
    now: datetime,
) -> tuple[int, int]:
    """Merge rendered ``(fingerprint, uri)`` pairs; returns ``(added, refreshed)``."""
    timestamp = _utc_timestamp(now)
    entries = pool.entries(protocol)
    added = refreshed = 0
    for fingerprint, uri in rendered:
        entry = entries.get(fingerprint)
        if entry is None:
            entries[fingerprint] = PoolEntry(
                uri=uri, first_added_at=timestamp, last_seen_at=timestamp
            )
            added += 1
            continue
        entry.last_seen_at = timestamp
        entry.hits += 1
        refreshed += 1
    return added, refreshed


def enforce_cap(pool: ProfilePool, protocol: str, cap: int) -> int:
    """Evict the least recently seen entries beyond the cap; returns evictions."""
    entries = pool.entries(protocol)
    excess = len(entries) - cap
    if excess <= 0:
        return 0
    oldest_first = sorted(
        entries.items(), key=lambda item: (item[1].last_seen_at, item[1].first_added_at, item[0])
    )
    for fingerprint, _ in oldest_first[:excess]:
        del entries[fingerprint]
    return excess


def render_lines(entries: Mapping[str, PoolEntry]) -> list[str]:
    """Render URIs in the pool's stable order, keeping git diffs readable."""
    return [entry.uri for entry in entries.values()]


@dataclass(frozen=True, slots=True)
class AccumulationReport:
    """Aggregate outcome of one accumulate-and-publish step."""

    reset_this_run: bool
    cycle_started_at: str
    cycle_day: int
    days_until_reset: int
    cap_per_protocol: int
    added_by_protocol: dict[str, int]
    refreshed_by_protocol: dict[str, int]
    carried_by_protocol: dict[str, int]
    evicted_by_protocol: dict[str, int]
    total_by_protocol: dict[str, int]

    @property
    def new_profiles(self) -> int:
        return sum(self.added_by_protocol.values())

    def as_report_payload(self) -> dict[str, object]:
        """Redacted publication block for the JSON audit report."""
        return {
            "mode": "accumulate",
            "cap_per_protocol": self.cap_per_protocol,
            "cycle": {
                "started_at": self.cycle_started_at,
                "day": self.cycle_day,
                "days_until_reset": self.days_until_reset,
                "reset_this_run": self.reset_this_run,
            },
            "added": dict(sorted(self.added_by_protocol.items())),
            "refreshed": dict(sorted(self.refreshed_by_protocol.items())),
            "carried": dict(sorted(self.carried_by_protocol.items())),
            "evicted": dict(sorted(self.evicted_by_protocol.items())),
            "total": dict(sorted(self.total_by_protocol.items())),
        }
