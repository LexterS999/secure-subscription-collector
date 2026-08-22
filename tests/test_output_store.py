from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from subscription_collector.config_loader import PublicationConfig
from subscription_collector.output_store import OUTPUT_FILENAMES, publish_profiles
from subscription_collector.parser import parse_profile

VLESS_TLS = (
    "vless://123e4567-e89b-12d3-a456-426614174000@vless.example.org:443"
    "?encryption=none&security=tls&sni=www.example.com&fp=chrome&type=grpc#source"
)
TROJAN_TLS = (
    "trojan://correct-horse@node.example.org:443"
    "?security=tls&sni=www.example.com&fp=chrome&type=tcp#source"
)
HY2_TLS = "hy2://hy2-password@hy2.example.org:443?security=tls&sni=www.example.com#source"

RUN_ONE = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


def _profile(uri: str):
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    return profile


def _publish(
    tmp_path: Path,
    profiles,
    *,
    now: datetime = RUN_ONE,
    **publication_overrides: object,
):
    """Run one accumulating publication against a per-test pool file."""
    return publish_profiles(
        tmp_path / "output",
        profiles,
        pool_path=tmp_path / "profile_pool.json",
        settings=PublicationConfig(**publication_overrides),
        now=now,
    )


def test_publish_profiles_creates_all_protocol_files_and_separates_profiles(tmp_path: Path) -> None:
    """Creates stable protocol files without a proxy checker and routes each URI correctly."""
    summary = _publish(
        tmp_path,
        [_profile(VLESS_TLS), _profile(TROJAN_TLS), _profile(HY2_TLS)],
    )

    output_dir = tmp_path / "output"
    assert {path.name for path in output_dir.iterdir()} == set(OUTPUT_FILENAMES.values())
    assert "vless://" in (output_dir / "vless.txt").read_text(encoding="utf-8")
    assert "trojan://" in (output_dir / "trojan.txt").read_text(encoding="utf-8")
    assert "hy2://" in (output_dir / "hysteria2.txt").read_text(encoding="utf-8")
    assert summary.added_by_protocol == {"vless": 1, "trojan": 1, "hysteria2": 1}
    assert summary.total_by_protocol == {"vless": 1, "trojan": 1, "hysteria2": 1}


def test_publish_profiles_accumulates_history_across_runs(tmp_path: Path) -> None:
    """Keeps previously published profiles and appends newly validated ones."""
    second_run = RUN_ONE + timedelta(hours=3)
    first = _profile(TROJAN_TLS)
    second = _profile(TROJAN_TLS.replace("node.example.org", "new.example.org"))

    _publish(tmp_path, [first])
    summary = _publish(tmp_path, [second], now=second_run)

    lines = (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert any("node.example.org" in line for line in lines)
    assert any("new.example.org" in line for line in lines)
    assert summary.added_by_protocol["trojan"] == 1
    assert summary.carried_by_protocol["trojan"] == 1
    assert summary.total_by_protocol["trojan"] == 2


def test_publish_profiles_deduplicates_cosmetic_duplicate_in_current_run(tmp_path: Path) -> None:
    """Treats a changed URI fragment and query order as one current Android-client profile."""
    first = _profile(TROJAN_TLS)
    reordered = _profile(
        "trojan://correct-horse@node.example.org:443?type=tcp&fp=chrome&"
        "sni=www.example.com&security=tls#different-name"
    )

    summary = _publish(tmp_path, [first, reordered])

    assert (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").count("\n") == 1
    assert summary.added_by_protocol["trojan"] == 1
    assert summary.refreshed_by_protocol["trojan"] == 0
    assert summary.total_by_protocol["trojan"] == 1


def test_publish_profiles_preserves_sni_distinct_profiles(tmp_path: Path) -> None:
    """Does not collapse profiles sharing an endpoint but using materially different SNI values."""
    first = _profile(TROJAN_TLS.replace("www.example.com", "a.example"))
    second = _profile(TROJAN_TLS.replace("www.example.com", "b.example"))

    _publish(tmp_path, [first, second])

    assert (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").count("\n") == 2


def test_publish_profiles_evicts_oldest_beyond_per_protocol_cap(tmp_path: Path) -> None:
    """Enforces the hard cap by evicting the least recently seen entries first."""
    hosts = ("node1.example.org", "node2.example.org", "node3.example.org")
    _publish(tmp_path, [_profile(TROJAN_TLS.replace("node.example.org", hosts[0]))])
    _publish(tmp_path, [_profile(TROJAN_TLS.replace("node.example.org", hosts[1]))],
             now=RUN_ONE + timedelta(hours=1))
    summary = _publish(
        tmp_path,
        [_profile(TROJAN_TLS.replace("node.example.org", hosts[2]))],
        now=RUN_ONE + timedelta(hours=2),
        max_profiles_per_protocol=2,
    )

    lines = (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    joined = "\n".join(lines)
    assert "node1.example.org" not in joined
    assert "node2.example.org" in joined and "node3.example.org" in joined
    assert summary.evicted_by_protocol["trojan"] == 1


def test_publish_profiles_resets_pool_on_the_seventh_day(tmp_path: Path) -> None:
    """Day seven starts a fresh cycle: the pool drops to zero before new merges."""
    seventh_day = RUN_ONE + timedelta(days=7)
    _publish(tmp_path, [_profile(TROJAN_TLS)])
    summary = _publish(
        tmp_path,
        [_profile(TROJAN_TLS.replace("node.example.org", "fresh.example.org"))],
        now=seventh_day,
    )

    lines = (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "fresh.example.org" in lines[0]
    assert "node.example.org" not in lines[0]
    assert summary.reset_this_run is True
    assert summary.cycle_day == 1
    assert summary.carried_by_protocol["trojan"] == 0
    assert summary.total_by_protocol["trojan"] == 1


def test_publish_profiles_keeps_accumulating_until_day_seven(tmp_path: Path) -> None:
    """A run inside the six-day window carries history instead of resetting it."""
    sixth_day = RUN_ONE + timedelta(days=5, hours=23)
    _publish(tmp_path, [_profile(TROJAN_TLS)])
    summary = _publish(
        tmp_path,
        [_profile(TROJAN_TLS.replace("node.example.org", "fresh.example.org"))],
        now=sixth_day,
    )

    lines = (tmp_path / "output" / "trojan.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert summary.reset_this_run is False
    assert summary.cycle_day == 6
    assert summary.days_until_reset == 1
