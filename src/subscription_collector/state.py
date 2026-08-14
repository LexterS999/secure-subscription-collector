from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .models import SeenRecord
from .writer import write_json_atomic


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_state(path: Path) -> dict[str, SeenRecord]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    records: dict[str, SeenRecord] = {}
    for fingerprint, record in payload.items():
        if (
            isinstance(fingerprint, str)
            and len(fingerprint) == 64
            and isinstance(record, dict)
            and isinstance(record.get("first_seen_at"), str)
            and isinstance(record.get("last_seen_at"), str)
        ):
            records[fingerprint] = SeenRecord(record["first_seen_at"], record["last_seen_at"])
    return records


def update_state(path: Path, fingerprints: list[str], now: datetime) -> dict[str, SeenRecord]:
    """Update only fingerprint timestamps and atomically persist the compact state."""
    current = _load_state(path)
    timestamp = _utc_timestamp(now)
    updated: dict[str, SeenRecord] = dict(current)
    for fingerprint in fingerprints:
        previous = current.get(fingerprint)
        updated[fingerprint] = SeenRecord(
            first_seen_at=previous.first_seen_at if previous else timestamp,
            last_seen_at=timestamp,
        )
    write_json_atomic(
        path,
        {
            fingerprint: {
                "first_seen_at": record.first_seen_at,
                "last_seen_at": record.last_seen_at,
            }
            for fingerprint, record in sorted(updated.items())
        },
    )
    return updated
