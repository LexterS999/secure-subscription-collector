from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from math import pow

from .config_loader import ChannelQualityConfig


@dataclass(frozen=True, slots=True)
class ChannelMetrics:
    """Redacted aggregate inputs from one public Telegram preview observation."""

    preview_available: bool
    fresh_posts: int
    all_uri_candidates: int
    supported_candidates: int
    static_accepted: int
    unique_profiles: int
    duplicate_posts: int = 0
    xray_passed: int = 0
    xray_failed: int = 0


@dataclass(frozen=True, slots=True)
class ChannelStateRecord:
    status: str
    score: float
    reason: str
    evidence_runs: int
    first_seen_at: str
    last_seen_at: str
    last_evaluated_at: str
    confidence: float = 0.0
    required_score: float = 100.0
    xray_successes: int = 0
    xray_failures: int = 0


@dataclass(frozen=True, slots=True)
class ChannelEvaluation:
    handle: str
    status: str
    score: float
    reason: str
    evidence_runs: int
    observed_at: str
    first_seen_at: str
    confidence: float
    required_score: float
    xray_successes: int
    xray_failures: int

    def to_state_record(self) -> ChannelStateRecord:
        return ChannelStateRecord(
            status=self.status,
            score=self.score,
            reason=self.reason,
            evidence_runs=self.evidence_runs,
            first_seen_at=self.first_seen_at,
            last_seen_at=self.observed_at,
            last_evaluated_at=self.observed_at,
            confidence=self.confidence,
            required_score=self.required_score,
            xray_successes=self.xray_successes,
            xray_failures=self.xray_failures,
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ratio(numerator: int, denominator: int) -> float:
    return max(0.0, numerator / max(1, denominator))


def _bounded(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def _run_score(metrics: ChannelMetrics, settings: ChannelQualityConfig) -> float:
    activity = min(1.0, _ratio(metrics.fresh_posts, settings.min_fresh_posts))
    supported_yield = _ratio(metrics.supported_candidates, metrics.all_uri_candidates)
    static_security = _ratio(metrics.static_accepted, metrics.supported_candidates)
    uniqueness = _ratio(metrics.unique_profiles, metrics.static_accepted)
    nonduplication = (
        1.0
        if metrics.fresh_posts < 2
        else _bounded(1.0 - _ratio(metrics.duplicate_posts, metrics.fresh_posts))
    )
    xray_total = metrics.xray_passed + metrics.xray_failed
    xray_result = _ratio(
        metrics.xray_passed + settings.xray_prior_successes,
        xray_total + settings.xray_prior_successes + settings.xray_prior_failures,
    )
    return round(
        activity * settings.activity_weight
        + supported_yield * settings.supported_yield_weight
        + static_security * settings.static_security_weight
        + uniqueness * settings.uniqueness_weight
        + nonduplication * settings.nonduplication_weight
        + xray_result * settings.xray_weight,
        2,
    )


def _history_retention(
    previous: ChannelStateRecord,
    observed_at: datetime,
    half_life_hours: float,
) -> float:
    try:
        prior_time = datetime.fromisoformat(previous.last_evaluated_at.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    elapsed_hours = max(1.0, (observed_at.astimezone(UTC) - prior_time).total_seconds() / 3600)
    return _bounded(pow(0.5, elapsed_hours / half_life_hours))


def _confidence(
    metrics: ChannelMetrics,
    evidence_runs: int,
    settings: ChannelQualityConfig,
) -> float:
    evidence = min(1.0, evidence_runs / settings.min_evidence_runs)
    activity = min(1.0, metrics.fresh_posts / settings.min_fresh_posts)
    xray_total = metrics.xray_passed + metrics.xray_failed
    xray = min(1.0, xray_total / settings.min_supported_candidates)
    return round(0.5 * evidence + 0.3 * activity + 0.2 * xray, 4)


def evaluate_channel(
    handle: str,
    metrics: ChannelMetrics,
    previous: ChannelStateRecord | None,
    settings: ChannelQualityConfig,
    observed_at: datetime,
) -> ChannelEvaluation:
    """Score a public source using observable data with bounded historical memory."""
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
            confidence=previous.confidence,
            required_score=previous.required_score,
            xray_successes=previous.xray_successes,
            xray_failures=previous.xray_failures,
        )

    evidence_runs = (previous.evidence_runs if previous is not None else 0) + 1
    run_score = _run_score(metrics, settings)
    xray_successes = (previous.xray_successes if previous is not None else 0) + metrics.xray_passed
    xray_failures = (previous.xray_failures if previous is not None else 0) + metrics.xray_failed
    confidence = _confidence(metrics, evidence_runs, settings)
    required_score = round(
        settings.approval_score + (1.0 - confidence) * settings.new_channel_margin,
        2,
    )

    if previous is None or (previous.status == "excluded" and run_score >= required_score):
        score = run_score
    else:
        retention = _history_retention(previous, observed_at, settings.history_half_life_hours)
        score = round(previous.score * retention + run_score * (1.0 - retention), 2)

    if evidence_runs < settings.min_evidence_runs:
        status = "candidate"
        reason = "insufficient_evidence"
    elif metrics.fresh_posts < settings.min_fresh_posts:
        status = "excluded"
        reason = "insufficient_fresh_posts"
    elif metrics.supported_candidates < settings.min_supported_candidates:
        status = "excluded"
        reason = "insufficient_candidates"
    elif confidence < settings.minimum_confidence:
        status = "watch"
        reason = "insufficient_confidence"
    elif xray_successes < 1:
        status = "watch"
        reason = "no_xray_success"
    elif score >= required_score:
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
        confidence=confidence,
        required_score=required_score,
        xray_successes=xray_successes,
        xray_failures=xray_failures,
    )
