from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Protocol(StrEnum):
    VLESS = "vless"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"


class Freshness(StrEnum):
    RECENT = "recent"
    UNKNOWN = "unknown"
    STALE = "stale"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Profile:
    protocol: Protocol
    server: str
    port: int
    username: str | None
    secret: str | None
    security: str
    transport: str
    params: Mapping[str, str] = field(default_factory=dict)
    source_url: str = ""
    original_uri: str = ""

    def __post_init__(self) -> None:
        if not self.server or any(character.isspace() for character in self.server):
            raise ValueError("server must be a non-empty hostname or IP address")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class SourceResult:
    source_url: str
    freshness: Freshness
    text: str | None
    last_modified: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    profile: Profile | None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class SeenRecord:
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True, slots=True)
class TelegramPost:
    """Redacted public preview post with only collection-relevant fields."""

    handle: str
    message_id: str
    published_at: str
    text: str
    hrefs: tuple[str, ...] = ()


@dataclass(slots=True)
class RunStats:
    input_sources: int = 0
    fetched_sources: int = 0
    source_freshness: dict[str, int] = field(default_factory=dict)
    candidate_lines: int = 0
    parsed_profiles: int = 0
    accepted_profiles: int = 0
    unique_profiles: int = 0
    checked_endpoints: int = 0
    responsive_endpoints: int = 0
    timing_ms: dict[str, int] = field(default_factory=dict)
    emitted_profiles: int = 0
    published_new_by_protocol: dict[str, int] = field(default_factory=dict)
    published_total_by_protocol: dict[str, int] = field(default_factory=dict)
    excluded: dict[str, int] = field(default_factory=dict)

    def exclude(self, reason: str) -> None:
        self.excluded[reason] = self.excluded.get(reason, 0) + 1
