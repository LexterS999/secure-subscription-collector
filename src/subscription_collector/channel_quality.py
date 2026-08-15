from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .config_loader import ChannelQualityConfig


@dataclass(frozen=True, slots=True)
class ChannelMetrics:
    """Redacted per-run aggregate inputs to a channel quality decision."""

    preview_available: bool
    fresh_posts: int
    all_uri_candidates: int
    supported_candidates: int
    static_accepted: int
    unique_profiles: int
    xray_passed: int
    xray_failed: int


@dataclass(frozen=True, slots=True)
class ChannelStateRecord:
    status: str
    score: float
    reason: str
    evidence_runs: int
    alpha_success: int
    beta_failure: int
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
    alpha_success: int
    beta_failure: int
    observed_at: str
    first_seen_at: str

    def to_state_record(self) -> ChannelStateRecord:
        return ChannelStateRecord(
            status=self.status,
            score=self.score,
            reason=self.reason,
            evidence_runs=self.evidence_runs,
            alpha_success=self.alpha_success,
            beta_failure=self.beta_failure,
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
    """Score a channel using redacted metrics and evidence-aware Xray outcomes."""
    timestamp = _timestamp(observed_at)
    if previous is not None and not metrics.preview_available:
        return ChannelEvaluation(
            handle=handle,
            status=previous.status,
            score=previous.score,
            reason="preview_unavailable",
            evidence_runs=previous.evidence_runs,
            alpha_success=previous.alpha_success,
            beta_failure=previous.beta_failure,
            observed_at=timestamp,
            first_seen_at=previous.first_seen_at,
        )
    alpha = (previous.alpha_success if previous is not None else 1) + metrics.xray_passed
    beta = (previous.beta_failure if previous is not None else 1) + metrics.xray_failed
    evidence_runs = (previous.evidence_runs if previous is not None else 0) + 1

    availability = 10.0 if metrics.preview_available else 0.0
    activity = min(1.0, _ratio(metrics.fresh_posts, settings.min_fresh_posts)) * 10.0
    supported_yield = _ratio(metrics.supported_candidates, metrics.all_uri_candidates) * 15.0
    security = _ratio(metrics.static_accepted, metrics.supported_candidates) * 20.0
    uniqueness = _ratio(metrics.unique_profiles, metrics.static_accepted) * 15.0
    xray_viability = _ratio(alpha, alpha + beta) * 20.0
    stability = min(1.0, _ratio(evidence_runs, settings.min_evidence_runs)) * 10.0
    score = round(
        availability
        + activity
        + supported_yield
        + security
        + uniqueness
        + xray_viability
        + stability,
        2,
    )

    if previous is not None and previous.status == "excluded":
        status = "excluded"
        reason = "previously_excluded"
    elif metrics.supported_candidates < settings.min_supported_candidates:
        status = "candidate" if evidence_runs < settings.min_evidence_runs else "excluded"
        reason = "insufficient_candidates"
    elif evidence_runs < settings.min_evidence_runs:
        status = "candidate"
        reason = "insufficient_evidence"
    elif alpha <= 1:
        status = "excluded"
        reason = "no_xray_success"
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
        alpha_success=alpha,
        beta_failure=beta,
        observed_at=timestamp,
        first_seen_at=previous.first_seen_at if previous is not None else timestamp,
    )
