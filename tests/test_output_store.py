from __future__ import annotations

from pathlib import Path

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
TUIC_V5 = (
    "tuic://123e4567-e89b-12d3-a456-426614174000:tuic-password@tuic.example.org:443"
    "?security=tls&sni=www.example.com&version=5#source"
)


def _profile(uri: str):
    profile = parse_profile(uri, "https://source.example/list")
    assert profile is not None
    return profile


def test_publish_profiles_creates_all_protocol_files_and_separates_profiles(tmp_path: Path) -> None:
    """Creates stable protocol files without a proxy checker and routes each URI correctly."""
    summary = publish_profiles(
        tmp_path / "output",
        [_profile(VLESS_TLS), _profile(TROJAN_TLS), _profile(HY2_TLS), _profile(TUIC_V5)],
    )

    output_dir = tmp_path / "output"
    assert {path.name for path in output_dir.iterdir()} == set(OUTPUT_FILENAMES.values())
    assert "vless://" in (output_dir / "vless.txt").read_text(encoding="utf-8")
    assert "trojan://" in (output_dir / "trojan.txt").read_text(encoding="utf-8")
    assert "hy2://" in (output_dir / "hysteria2.txt").read_text(encoding="utf-8")
    assert "tuic://" in (output_dir / "tuic.txt").read_text(encoding="utf-8")
    assert summary.new_by_protocol == {"vless": 1, "trojan": 1, "hysteria2": 1, "tuic": 1}
    assert summary.total_by_protocol == {"vless": 1, "trojan": 1, "hysteria2": 1, "tuic": 1}


def test_publish_profiles_preserves_history_and_appends_only_new_profiles(tmp_path: Path) -> None:
    """Preserves earlier records in order while adding a previously unseen profile."""
    output_dir = tmp_path / "output"
    first = _profile(TROJAN_TLS)
    second = _profile(TROJAN_TLS.replace("node.example.org", "new.example.org"))

    publish_profiles(output_dir, [first])
    summary = publish_profiles(output_dir, [second])

    lines = (output_dir / "trojan.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert "node.example.org" in lines[0]
    assert "new.example.org" in lines[1]
    assert summary.new_by_protocol["trojan"] == 1
    assert summary.total_by_protocol["trojan"] == 2


def test_publish_profiles_skips_historical_cosmetic_duplicate(tmp_path: Path) -> None:
    """Treats a changed URI fragment and query order as the same Android-client profile."""
    output_dir = tmp_path / "output"
    first = _profile(TROJAN_TLS)
    reordered = _profile(
        "trojan://correct-horse@node.example.org:443?type=tcp&fp=chrome&"
        "sni=www.example.com&security=tls#different-name"
    )

    publish_profiles(output_dir, [first])
    summary = publish_profiles(output_dir, [reordered])

    assert (output_dir / "trojan.txt").read_text(encoding="utf-8").count("\n") == 1
    assert summary.new_by_protocol["trojan"] == 0
    assert summary.total_by_protocol["trojan"] == 1


def test_publish_profiles_preserves_sni_distinct_profiles(tmp_path: Path) -> None:
    """Does not collapse profiles sharing an endpoint but using materially different SNI values."""
    output_dir = tmp_path / "output"
    first = _profile(TROJAN_TLS.replace("www.example.com", "a.example"))
    second = _profile(TROJAN_TLS.replace("www.example.com", "b.example"))

    publish_profiles(output_dir, [first, second])

    assert (output_dir / "trojan.txt").read_text(encoding="utf-8").count("\n") == 2
