from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from .channel_quality import ChannelEvaluation, ChannelStateRecord
from .writer import write_json_atomic, write_text_atomic

_STATE_VERSION = 4
_VALID_STATUSES = {"candidate", "approved", "watch", "excluded"}


def channel_state_key(handle: str) -> str:
    """Return the stable redacted storage key for a normalized public handle."""
    return sha256(handle.encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_record(value: Any) -> ChannelStateRecord | None:
    if not isinstance(value, dict):
        return None
    required = {
        "status",
        "score",
        "reason",
        "evidence_runs",
        "first_seen_at",
        "last_seen_at",
        "last_evaluated_at",
        "confidence",
        "required_score",
        "deep_accepted",
        "deep_rejected",
    }
    if set(value) != required or value["status"] not in _VALID_STATUSES:
        return None
    if (
        isinstance(value["score"], bool)
        or not isinstance(value["score"], (int, float))
        or not 0 <= float(value["score"]) <= 100
    ):
        return None
    if (
        isinstance(value["evidence_runs"], bool)
        or not isinstance(value["evidence_runs"], int)
        or value["evidence_runs"] < 1
    ):
        return None
    for field, minimum, maximum in (("confidence", 0.0, 1.0), ("required_score", 0.0, 100.0)):
        if (
            isinstance(value[field], bool)
            or not isinstance(value[field], (int, float))
            or not minimum <= float(value[field]) <= maximum
        ):
            return None
    for field_name in ("deep_accepted", "deep_rejected"):
        if (
            isinstance(value[field_name], bool)
            or not isinstance(value[field_name], int)
            or value[field_name] < 0
        ):
            return None
    string_fields = ("reason", "first_seen_at", "last_seen_at", "last_evaluated_at")
    if any(not isinstance(value[field], str) or not value[field] for field in string_fields):
        return None
    return ChannelStateRecord(
        status=value["status"],
        score=round(float(value["score"]), 2),
        reason=value["reason"],
        evidence_runs=value["evidence_runs"],
        first_seen_at=value["first_seen_at"],
        last_seen_at=value["last_seen_at"],
        last_evaluated_at=value["last_evaluated_at"],
        confidence=round(float(value["confidence"]), 4),
        required_score=round(float(value["required_score"]), 2),
        deep_accepted=value["deep_accepted"],
        deep_rejected=value["deep_rejected"],
    )


def load_channel_state(path: Path) -> dict[str, ChannelStateRecord]:
    """Load current redacted state; records from prior schema versions are discarded."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != _STATE_VERSION:
        return {}
    channels = payload.get("channels")
    if not isinstance(channels, dict):
        return {}
    state: dict[str, ChannelStateRecord] = {}
    for key, value in channels.items():
        if not isinstance(key, str) or len(key) != 64:
            continue
        record = _parse_record(value)
        if record is not None:
            state[key] = record
    return state


def write_channel_registry(path: Path, handles: Iterable[str]) -> None:
    """Atomically publish the requested public-channel registry in stable order."""
    normalized = sorted({handle.lower() for handle in handles})
    write_text_atomic(path, "".join(f"@{handle}\n" for handle in normalized))


def update_channel_state(
    path: Path,
    evaluations: Mapping[str, ChannelEvaluation],
    observed_at: datetime,
) -> dict[str, ChannelStateRecord]:
    """Merge evaluations by hashed handle and atomically persist no public handle values."""
    state = load_channel_state(path)
    for handle, evaluation in evaluations.items():
        if handle != evaluation.handle:
            raise ValueError("channel evaluation key must match its handle")
        state[channel_state_key(handle)] = evaluation.to_state_record()
    payload = {
        "version": _STATE_VERSION,
        "generated_at": _timestamp(observed_at),
        "channels": {
            key: {
                "status": record.status,
                "score": record.score,
                "reason": record.reason,
                "evidence_runs": record.evidence_runs,
                "first_seen_at": record.first_seen_at,
                "last_seen_at": record.last_seen_at,
                "last_evaluated_at": record.last_evaluated_at,
                "confidence": record.confidence,
                "required_score": record.required_score,
                "deep_accepted": record.deep_accepted,
                "deep_rejected": record.deep_rejected,
            }
            for key, record in sorted(state.items())
        },
    }
    write_json_atomic(path, payload)
    return state
