from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .dedup import deduplicate, profile_fingerprint
from .models import Profile, Protocol
from .renamer import render_named_uri
from .writer import write_text_atomic

OUTPUT_FILENAMES: Mapping[Protocol, str] = {
    Protocol.VLESS: "vless.txt",
    Protocol.TROJAN: "trojan.txt",
    Protocol.HYSTERIA2: "hysteria2.txt",
}


@dataclass(frozen=True, slots=True)
class PublicationSummary:
    """Safe aggregate result of atomically replacing protocol-specific profile files."""

    new_by_protocol: dict[str, int]
    total_by_protocol: dict[str, int]

    @property
    def new_profiles(self) -> int:
        return sum(self.new_by_protocol.values())


def _profiles_by_protocol(profiles: Iterable[Profile]) -> dict[Protocol, list[Profile]]:
    grouped = {protocol: [] for protocol in OUTPUT_FILENAMES}
    for profile in profiles:
        grouped[profile.protocol].append(profile)
    return grouped


def publish_profiles(output_dir: Path, profiles: Iterable[Profile]) -> PublicationSummary:
    """Atomically publish only profiles that passed validation in the current collection run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    current_by_protocol = _profiles_by_protocol(profiles)
    new_by_protocol: dict[str, int] = {}
    total_by_protocol: dict[str, int] = {}

    for protocol, filename in OUTPUT_FILENAMES.items():
        output_path = output_dir / filename
        current_unique = deduplicate(current_by_protocol[protocol])
        output_lines = [
            render_named_uri(profile, profile_fingerprint(profile)) for profile in current_unique
        ]
        write_text_atomic(output_path, "\n".join(output_lines) + ("\n" if output_lines else ""))
        new_by_protocol[protocol.value] = len(current_unique)
        total_by_protocol[protocol.value] = len(current_unique)

    return PublicationSummary(
        new_by_protocol=new_by_protocol,
        total_by_protocol=total_by_protocol,
    )
