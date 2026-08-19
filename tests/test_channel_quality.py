import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from subscription_collector.channel_quality import ChannelMetrics, evaluate_channel
from subscription_collector.channel_state import (
    load_channel_state,
    update_channel_state,
    write_channel_registry,
)
from subscription_collector.config_loader import ChannelQualityConfig

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
SETTINGS = ChannelQualityConfig(
    approval_score=55.0,
    min_evidence_runs=2,
    min_supported_candidates=2,
    min_fresh_posts=2,
)
HEALTHY = ChannelMetrics(
    preview_available=True,
    fresh_posts=2,
    all_uri_candidates=2,
    supported_candidates=2,
    static_accepted=2,
    unique_profiles=2,
    xray_passed=2,
)
EMPTY = ChannelMetrics(
    preview_available=True,
    fresh_posts=0,
    all_uri_candidates=0,
    supported_candidates=0,
    static_accepted=0,
    unique_profiles=0,
)


def test_candidate_requires_two_evidence_runs_before_approval() -> None:
    evaluation = evaluate_channel("quality_channel", HEALTHY, None, SETTINGS, NOW)

    assert evaluation.status == "candidate"
    assert evaluation.reason == "insufficient_evidence"
    assert evaluation.evidence_runs == 1
    assert evaluation.score > SETTINGS.approval_score


def test_second_healthy_evaluation_approves_channel() -> None:
    first = evaluate_channel("quality_channel", HEALTHY, None, SETTINGS, NOW)
    second = evaluate_channel("quality_channel", HEALTHY, first.to_state_record(), SETTINGS, NOW)

    assert second.status == "approved"
    assert second.evidence_runs == 2
    assert second.score >= SETTINGS.approval_score


def test_low_quality_channel_is_excluded_after_enough_evidence() -> None:
    first = evaluate_channel("quality_channel", EMPTY, None, SETTINGS, NOW)
    second = evaluate_channel("quality_channel", EMPTY, first.to_state_record(), SETTINGS, NOW)

    assert second.status == "excluded"
    assert second.reason == "insufficient_fresh_posts"


def test_excluded_channel_can_recover_when_new_content_meets_quality_threshold() -> None:
    first = evaluate_channel("quality_channel", EMPTY, None, SETTINGS, NOW)
    excluded = evaluate_channel("quality_channel", EMPTY, first.to_state_record(), SETTINGS, NOW)
    recovered = evaluate_channel(
        "quality_channel",
        HEALTHY,
        excluded.to_state_record(),
        SETTINGS,
        NOW,
    )

    assert recovered.status == "approved"
    assert recovered.reason == "approved"


def test_registry_is_sorted_and_state_uses_hashed_channel_key(tmp_path: Path) -> None:
    registry = tmp_path / "tg_channels"
    state_path = tmp_path / "channel_state.json"
    write_channel_registry(registry, {"beta_name", "alpha_name"})

    evaluation = evaluate_channel("alpha_name", HEALTHY, None, SETTINGS, NOW)
    update_channel_state(state_path, {"alpha_name": evaluation}, NOW)
    state = load_channel_state(state_path)

    assert registry.read_text(encoding="utf-8") == "@alpha_name\n@beta_name\n"
    assert set(state) == {sha256(b"alpha_name").hexdigest()}
    assert "alpha_name" not in state_path.read_text(encoding="utf-8")


def test_preview_transport_failure_preserves_existing_approved_channel() -> None:
    first = evaluate_channel("quality_channel", HEALTHY, None, SETTINGS, NOW)
    approved = evaluate_channel("quality_channel", HEALTHY, first.to_state_record(), SETTINGS, NOW)
    unavailable = ChannelMetrics(
        preview_available=False,
        fresh_posts=0,
        all_uri_candidates=0,
        supported_candidates=0,
        static_accepted=0,
        unique_profiles=0,
    )

    result = evaluate_channel(
        "quality_channel",
        unavailable,
        approved.to_state_record(),
        SETTINGS,
        NOW,
    )

    assert result.status == "approved"
    assert result.reason == "preview_unavailable"
    assert result.evidence_runs == approved.evidence_runs


def test_adaptive_quality_increases_after_successful_xray_observation() -> None:
    """Prevent Xray outcomes from being ignored by the approved adaptive model."""
    failed = ChannelMetrics(
        preview_available=True,
        fresh_posts=2,
        all_uri_candidates=2,
        supported_candidates=2,
        static_accepted=2,
        unique_profiles=2,
        duplicate_posts=0,
        xray_passed=0,
        xray_failed=3,
    )
    recovered = ChannelMetrics(
        preview_available=True,
        fresh_posts=2,
        all_uri_candidates=2,
        supported_candidates=2,
        static_accepted=2,
        unique_profiles=2,
        duplicate_posts=0,
        xray_passed=3,
        xray_failed=0,
    )

    first = evaluate_channel("quality_channel", failed, None, SETTINGS, NOW)
    second = evaluate_channel("quality_channel", recovered, first.to_state_record(), SETTINGS, NOW)

    assert second.score > first.score
    assert second.confidence >= first.confidence
    assert second.required_score <= first.required_score


def test_legacy_xray_state_is_discarded_for_content_quality_migration(tmp_path: Path) -> None:
    state_path = tmp_path / "channel_state.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "channels": {
                    sha256(b"legacy").hexdigest(): {
                        "status": "excluded",
                        "score": 40.0,
                        "reason": "no_xray_success",
                        "evidence_runs": 2,
                        "alpha_success": 1,
                        "beta_failure": 5,
                        "first_seen_at": "2026-08-15T00:00:00Z",
                        "last_seen_at": "2026-08-15T00:00:00Z",
                        "last_evaluated_at": "2026-08-15T00:00:00Z",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert load_channel_state(state_path) == {}


def test_channel_state_round_trip_preserves_adaptive_evidence(tmp_path: Path) -> None:
    state_path = tmp_path / "channel_state.json"
    evaluation = evaluate_channel("quality_channel", HEALTHY, None, SETTINGS, NOW)

    update_channel_state(state_path, {"quality_channel": evaluation}, NOW)
    restored = next(iter(load_channel_state(state_path).values()))

    assert restored.confidence == evaluation.confidence
    assert restored.required_score == evaluation.required_score
    assert restored.xray_successes == evaluation.xray_successes
    assert restored.xray_failures == evaluation.xray_failures
