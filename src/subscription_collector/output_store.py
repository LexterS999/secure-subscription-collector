from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .dedup import deduplicate, profile_fingerprint
from .models import Profile, Protocol
from .parser import parse_profile
from .policy import evaluate_strict_secure
from .renamer import render_named_uri
from .writer import write_text_atomic

OUTPUT_FILENAMES: Mapping[Protocol, str] = {
    Protocol.VLESS: "vless.txt",
    Protocol.TROJAN: "trojan.txt",
    Protocol.HYSTERIA2: "hysteria2.txt",
    Protocol.TUIC: "tuic.txt",
}


@dataclass(frozen=True, slots=True)
class PublicationSummary:
    """Safe aggregate result of writing protocol-specific accumulated profile files."""

    new_by_protocol: dict[str, int]
    total_by_protocol: dict[str, int]

    @property
    def new_profiles(self) -> int:
        return sum(self.new_by_protocol.values())


def _load_historical_profiles(path: Path, expected_protocol: Protocol) -> list[Profile]:
    """Read only statically valid historical entries belonging to the target protocol."""
    if not path.is_file():
        return []

    profiles: list[Profile] = []
    source_url = path.resolve().as_uri()
    for line in path.read_text(encoding="utf-8").splitlines():
        profile = parse_profile(line, source_url)
        if profile is None or profile.protocol is not expected_protocol:
            continue
        if evaluate_strict_secure(profile).profile is None:
            continue
        profiles.append(profile)
    return deduplicate(profiles)


def _profiles_by_protocol(profiles: Iterable[Profile]) -> dict[Protocol, list[Profile]]:
    grouped = {protocol: [] for protocol in OUTPUT_FILENAMES}
    for profile in profiles:
        grouped[profile.protocol].append(profile)
    return grouped


def publish_profiles(output_dir: Path, profiles: Iterable[Profile]) -> PublicationSummary:
    """Merge current profiles with persisted history and atomically publish each protocol file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    current_by_protocol = _profiles_by_protocol(profiles)
    new_by_protocol: dict[str, int] = {}
    total_by_protocol: dict[str, int] = {}

    for protocol, filename in OUTPUT_FILENAMES.items():
        output_path = output_dir / filename
        historical = _load_historical_profiles(output_path, protocol)
        historical_fingerprints = {profile_fingerprint(profile) for profile in historical}
        current_unique = deduplicate(current_by_protocol[protocol])
        new_profiles = [
            profile
            for profile in current_unique
            if profile_fingerprint(profile) not in historical_fingerprints
        ]
        merged = deduplicate([*historical, *new_profiles])
        output_lines = [
            render_named_uri(profile, profile_fingerprint(profile)) for profile in merged
        ]
        write_text_atomic(output_path, "\n".join(output_lines) + ("\n" if output_lines else ""))

        new_by_protocol[protocol.value] = len(new_profiles)
        total_by_protocol[protocol.value] = len(merged)

    return PublicationSummary(
        new_by_protocol=new_by_protocol,
        total_by_protocol=total_by_protocol,
    )
