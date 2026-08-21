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
    posts_with_profiles: int = 0
    total_text_length: int = 0
    span_hours: float = 0.0
    deep_passed: int = 0
    deep_failed: int = 0


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
    deep_accepted: int = 0
    deep_rejected: int = 0


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
    deep_accepted: int = 0
    deep_rejected: int = 0

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
            deep_accepted=self.deep_accepted,
            deep_rejected=self.deep_rejected,
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return max(0.0, float(numerator) / max(1.0, float(denominator)))


def _bounded(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def _component_weights(settings: ChannelQualityConfig) -> dict[str, float]:
    return {
        "activity": settings.activity_weight,
        "supported_yield": settings.supported_yield_weight,
        "static_security": settings.static_security_weight,
        "uniqueness": settings.uniqueness_weight,
        "nonduplication": settings.nonduplication_weight,
        "profile_coverage": settings.profile_coverage_weight,
        "text_depth": settings.text_depth_weight,
        "cadence": settings.cadence_weight,
        "depth": settings.depth_weight,
    }


def _deep_pass_rate(metrics: ChannelMetrics, settings: ChannelQualityConfig) -> float:
    """Laplace-smoothed share of profiles that survived the deep analysis."""
    prior_passes = max(0.0, settings.analysis_prior_passes)
    prior_failures = max(0.0, settings.analysis_prior_failures)
    passed = max(0, metrics.deep_passed)
    failed = max(0, metrics.deep_failed)
    total = prior_passes + prior_failures + passed + failed
    if total <= 0:
        return 0.5
    return (prior_passes + passed) / total


def _run_score(
    metrics: ChannelMetrics,
    settings: ChannelQualityConfig,
) -> float:
    activity = min(1.0, _ratio(metrics.fresh_posts, settings.min_fresh_posts))
    supported_yield = _ratio(metrics.supported_candidates, metrics.all_uri_candidates)
    static_security = _ratio(metrics.static_accepted, metrics.supported_candidates)
    uniqueness = _ratio(metrics.unique_profiles, metrics.static_accepted)
    nonduplication = (
        1.0
        if metrics.supported_candidates < 2
        else _bounded(1.0 - _ratio(metrics.duplicate_posts, metrics.supported_candidates))
    )
    profile_coverage = _ratio(metrics.posts_with_profiles, metrics.fresh_posts)
    components = {
        "activity": activity,
        "supported_yield": supported_yield,
        "static_security": static_security,
        "uniqueness": uniqueness,
        "nonduplication": nonduplication,
        "profile_coverage": profile_coverage,
        "text_depth": _text_depth(metrics),
        "cadence": _cadence_score(metrics),
        "depth": _deep_pass_rate(metrics, settings),
    }
    weights = _component_weights(settings)
    weight_total = sum(weights.values()) or 1.0
    score = sum(components[key] * weights[key] for key in weights) / weight_total * 100.0
    return round(score, 2)


def _average_text_length(metrics: ChannelMetrics) -> float:
    return _ratio(metrics.total_text_length, metrics.fresh_posts)


def _text_depth(metrics: ChannelMetrics) -> float:
    average_length = _average_text_length(metrics)
    return _bounded((average_length - 24.0) / 176.0)


def _cadence_score(metrics: ChannelMetrics) -> float:
    if metrics.fresh_posts <= 0:
        return 0.0
    effective_window_hours = max(24.0, metrics.span_hours if metrics.span_hours > 0 else 24.0)
    posts_per_day = metrics.fresh_posts * 24.0 / effective_window_hours
    if posts_per_day < 1.0:
        return posts_per_day
    if posts_per_day <= 12.0:
        return 1.0
    if posts_per_day >= 48.0:
        return 0.0
    return _bounded(1.0 - (posts_per_day - 12.0) / 36.0)


def _confidence(
    metrics: ChannelMetrics,
    evidence_runs: int,
    settings: ChannelQualityConfig,
) -> float:
    evidence = min(1.0, evidence_runs / settings.min_evidence_runs)
    activity = min(1.0, metrics.fresh_posts / settings.min_fresh_posts)
    coverage = _ratio(metrics.posts_with_profiles, metrics.fresh_posts)
    confidence = 0.4 * evidence + 0.3 * activity + 0.3 * coverage
    return round(confidence, 4)


def _required_score(
    confidence: float,
    settings: ChannelQualityConfig,
) -> float:
    required = settings.approval_score + (1.0 - confidence) * settings.new_channel_margin
    return round(_bounded(required, 0.0, 100.0), 2)


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
            deep_accepted=previous.deep_accepted,
            deep_rejected=previous.deep_rejected,
        )

    evidence_runs = (previous.evidence_runs if previous is not None else 0) + 1
    deep_accepted = (previous.deep_accepted if previous is not None else 0) + max(
        0, metrics.deep_passed
    )
    deep_rejected = (previous.deep_rejected if previous is not None else 0) + max(
        0, metrics.deep_failed
    )
    confidence = _confidence(
        metrics,
        evidence_runs,
        settings,
    )
    required_score = _required_score(
        confidence,
        settings,
    )
    run_score = _run_score(
        metrics,
        settings,
    )

    if previous is None or (previous.status == "excluded" and run_score >= required_score):
        score = run_score
    else:
        prior_time = datetime.fromisoformat(previous.last_evaluated_at.replace("Z", "+00:00"))
        elapsed_hours = max(1.0, (observed_at.astimezone(UTC) - prior_time).total_seconds() / 3600)
        retention = _bounded(pow(0.5, elapsed_hours / settings.history_half_life_hours))
        retention *= _bounded(1.0 - confidence * 0.5, 0.2, 0.9)
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
    elif score >= required_score:
        status = "approved"
        reason = "approved"
    else:
        shortfall = required_score - score
        improving = previous is not None and score > previous.score
        if shortfall <= settings.near_threshold_margin or improving:
            status = "watch"
            reason = "near_threshold"
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
        deep_accepted=deep_accepted,
        deep_rejected=deep_rejected,
    )
