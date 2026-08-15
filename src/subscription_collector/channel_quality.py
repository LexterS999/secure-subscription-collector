from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .config_loader import ChannelQualityConfig


@dataclass(frozen=True, slots=True)
class ChannelMetrics:
    """Redacted per-run aggregate inputs to a content-quality decision."""

    preview_available: bool
    fresh_posts: int
    all_uri_candidates: int
    supported_candidates: int
    static_accepted: int
    unique_profiles: int


@dataclass(frozen=True, slots=True)
class ChannelStateRecord:
    status: str
    score: float
    reason: str
    evidence_runs: int
    first_seen_at: str
    last_seen_at: str
    last_evaluated_at: str


@dataclass(frozen=True, slots=True)
class ChannelEvaluation:
    handle: str
    status: str
    score: float
    reason: str
    evidence_runs: int
    observed_at: str
    first_seen_at: str

    def to_state_record(self) -> ChannelStateRecord:
        return ChannelStateRecord(
            status=self.status,
            score=self.score,
            reason=self.reason,
            evidence_runs=self.evidence_runs,
            first_seen_at=self.first_seen_at,
            last_seen_at=self.observed_at,
            last_evaluated_at=self.observed_at,
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / max(1, denominator)


def evaluate_channel(
    handle: str,
    metrics: ChannelMetrics,
    previous: ChannelStateRecord | None,
    settings: ChannelQualityConfig,
    observed_at: datetime,
) -> ChannelEvaluation:
    """Score a public Telegram source using observable, redacted content metrics."""
    timestamp = _timestamp(observed_at)
    if previous is not None and not metrics.preview_available:
        return ChannelEvaluation(
            handle=handle,
            status=previous.status,
            score=previous.score,
            reason="preview_unavailable",
            evidence_runs=previous.evidence_runs,
            observed_at=timestamp,
            first_seen_at=previous.first_seen_at,
        )

    evidence_runs = (previous.evidence_runs if previous is not None else 0) + 1
    availability = 15.0 if metrics.preview_available else 0.0
    activity = min(1.0, _ratio(metrics.fresh_posts, settings.min_fresh_posts)) * 20.0
    supported_yield = _ratio(metrics.supported_candidates, metrics.all_uri_candidates) * 20.0
    security = _ratio(metrics.static_accepted, metrics.supported_candidates) * 25.0
    uniqueness = _ratio(metrics.unique_profiles, metrics.static_accepted) * 20.0
    score = round(availability + activity + supported_yield + security + uniqueness, 2)

    if evidence_runs < settings.min_evidence_runs:
        status = "candidate"
        reason = "insufficient_evidence"
    elif metrics.fresh_posts < settings.min_fresh_posts:
        status = "excluded"
        reason = "insufficient_fresh_posts"
    elif metrics.supported_candidates < settings.min_supported_candidates:
        status = "excluded"
        reason = "insufficient_candidates"
    elif score >= settings.approval_score:
        status = "approved"
        reason = "approved"
    else:
        status = "excluded"
        reason = "below_approval_score"

    return ChannelEvaluation(
        handle=handle,
        status=status,
        score=score,
        reason=reason,
        evidence_runs=evidence_runs,
        observed_at=timestamp,
        first_seen_at=previous.first_seen_at if previous is not None else timestamp,
    )
