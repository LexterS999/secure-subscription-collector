from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from subscription_collector.accumulation import (
    PoolEntry,
    ProfilePool,
    enforce_cap,
    load_pool,
    merge_profiles,
    render_lines,
    roll_cycle,
    save_pool,
)

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


def _entry(uri: str = "trojan://a@example.org:443#x", **overrides: object) -> PoolEntry:
    values = {
        "uri": uri,
        "first_added_at": "2026-08-09T00:00:00Z",
        "last_seen_at": "2026-08-09T00:00:00Z",
        "hits": 1,
    }
    values.update(overrides)
    return PoolEntry(**values)  # type: ignore[arg-type]


def test_roll_cycle_resets_only_after_cycle_days() -> None:
    started = NOW - timedelta(days=5)
    pool = ProfilePool(cycle_started_at=started.isoformat().replace("+00:00", "Z"))
    pool.entries("trojan")["a" * 64] = _entry()

    assert roll_cycle(pool, NOW, 6) is False
    assert len(pool.entries("trojan")) == 1

    seventh_day = NOW + timedelta(days=1, hours=1)
    assert roll_cycle(pool, seventh_day, 6) is True
    assert len(pool.entries("trojan")) == 0
    assert pool.generation == 2
    assert pool.cycle_started_at == "2026-08-11T13:00:00Z"


def test_roll_cycle_self_heals_unparseable_cycle_start() -> None:
    pool = ProfilePool(cycle_started_at="not-a-date")
    pool.entries("vless")["b" * 64] = _entry()

    assert roll_cycle(pool, NOW, 6) is True
    assert len(pool.entries("vless")) == 0


def test_merge_profiles_adds_and_refreshes_without_duplicates() -> None:
    pool = ProfilePool()
    fingerprint = "c" * 64
    pool.entries("trojan")[fingerprint] = _entry(hits=1)

    added, refreshed = merge_profiles(
        pool, "trojan", [(fingerprint, "trojan://a@example.org:443#x")], NOW
    )

    assert (added, refreshed) == (0, 1)
    entry = pool.entries("trojan")[fingerprint]
    assert entry.hits == 2
    assert entry.last_seen_at == "2026-08-10T12:00:00Z"
    assert len(pool.entries("trojan")) == 1


def test_enforce_cap_evicts_oldest_last_seen_first() -> None:
    pool = ProfilePool()
    entries = pool.entries("vless")
    entries["d" * 64] = _entry(last_seen_at="2026-08-01T00:00:00Z")
    entries["e" * 64] = _entry(last_seen_at="2026-08-05T00:00:00Z")
    entries["f" * 64] = _entry(last_seen_at="2026-08-03T00:00:00Z")

    evicted = enforce_cap(pool, "vless", 2)

    assert evicted == 1
    assert set(entries) == {"e" * 64, "f" * 64}


def test_enforce_cap_ties_break_by_first_added_then_fingerprint() -> None:
    pool = ProfilePool()
    entries = pool.entries("hysteria2")
    entries["1" * 64] = _entry(
        last_seen_at="2026-08-05T00:00:00Z", first_added_at="2026-08-02T00:00:00Z"
    )
    entries["0" * 64] = _entry(
        last_seen_at="2026-08-05T00:00:00Z", first_added_at="2026-08-01T00:00:00Z"
    )

    assert enforce_cap(pool, "hysteria2", 1) == 1
    assert set(entries) == {"1" * 64}


def test_render_lines_preserves_insertion_order_oldest_first() -> None:
    pool = ProfilePool()
    merge_profiles(pool, "trojan", [("a" * 64, "trojan://old@x:1#o")], NOW)
    merge_profiles(pool, "trojan", [("b" * 64, "trojan://new@x:2#n")], NOW)

    assert render_lines(pool.entries("trojan")) == ["trojan://old@x:1#o", "trojan://new@x:2#n"]


def test_save_and_load_pool_roundtrip(tmp_path: Path) -> None:
    pool = ProfilePool(cycle_started_at="2026-08-08T06:30:00Z", generation=4)
    pool.entries("trojan")["a" * 64] = _entry(hits=3)
    path = tmp_path / "pool.json"

    save_pool(path, pool)
    restored = load_pool(path)

    assert restored.cycle_started_at == "2026-08-08T06:30:00Z"
    assert restored.generation == 4
    entry = restored.entries("trojan")["a" * 64]
    assert entry.uri == "trojan://a@example.org:443#x"
    assert entry.hits == 3


def test_load_pool_returns_fresh_on_corrupt_file(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    path.write_text("{not json", encoding="utf-8")

    pool = load_pool(path)

    assert pool.total() == 0
    assert pool.generation == 1


def test_load_pool_drops_malformed_entries(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    payload = {
        "schema": 1,
        "cycle_started_at": "2026-08-08T00:00:00Z",
        "generation": 2,
        "protocols": {
            "trojan": {
                "a" * 64: {"uri": "trojan://ok@x:1#k", "first_added_at": "t", "last_seen_at": "t"},
                "short": {"uri": "trojan://bad@x:2#k"},
                "b" * 64: {"first_added_at": "t", "last_seen_at": "t"},
            },
            42: {"c" * 64: {"uri": "x"}},
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    pool = load_pool(path)

    assert set(pool.entries("trojan")) == {"a" * 64}
def test_roll_cycle_anchors_fresh_pool_without_counting_a_reset() -> None:
    """The very first run starts cycle one instead of reporting an empty reset."""
    pool = ProfilePool()

    assert roll_cycle(pool, NOW, 6) is False
    assert pool.cycle_started_at == "2026-08-10T12:00:00Z"
    assert pool.generation == 1
