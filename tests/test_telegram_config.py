from pathlib import Path

from subscription_collector.config_loader import load_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_default_config_exposes_public_preview_window_without_unbounded_channels() -> None:
    """Pin the 72-hour window, the per-channel cap, and the adaptive quality gate."""
    config = load_config(PROJECT_ROOT / "config.yaml")

    assert config.paths.tg_channels_path == Path("output/tg_channels.txt")
    assert config.paths.telegram_state_path == Path(".collector/channel_state.json")
    assert config.paths.telegram_registry_path == Path(".collector/tg_registry.txt")
    assert config.telegram.max_post_age_hours == 72
    assert config.telegram.max_profiles_per_channel == 1000
    # Pagination stays bounded: one channel can never stretch a run into hours.
    assert config.telegram.max_pages_per_channel == 50
    assert config.telegram.reevaluation_interval == 3
    assert config.telegram.concurrency == 12
    assert config.telegram.timeout_seconds == 12.0
    assert config.telegram.connect_timeout_seconds == 10.0
    assert config.telegram.total_deadline_seconds == 25.0
    assert config.telegram.retries == 2
    assert config.telegram.retry_backoff_seconds == 1.0
    assert config.telegram.max_response_bytes == 5_242_880
    assert config.telegram.max_redirects == 3
    assert config.telegram.quality.approval_score == 45.0
    assert config.telegram.quality.min_evidence_runs == 2
    assert config.telegram.quality.min_supported_candidates == 1
    assert config.telegram.quality.min_fresh_posts == 1
    assert config.telegram.quality.minimum_confidence == 0.3
    assert config.telegram.quality.new_channel_margin == 8.0
    assert config.telegram.quality.near_threshold_margin == 12.0
    assert config.telegram.quality.history_half_life_hours == 72.0
    assert config.telegram.quality.analysis_prior_passes == 1.0
    assert config.telegram.quality.analysis_prior_failures == 1.0
    assert config.telegram.quality.evidence_discount == 2.0
    assert config.telegram.quality.discount_floor == 15.0
    assert config.telegram.quality.momentum_cap == 5.0
    assert config.telegram.quality.relative_approval is True
    assert config.telegram.quality.relative_floor == 10.0
    assert config.telegram.quality.profile_coverage_weight == 10.0
    assert config.telegram.quality.text_depth_weight == 5.0
    assert config.telegram.quality.cadence_weight == 5.0
    assert config.telegram.quality.depth_weight == 15.0


def test_default_config_pins_tcp_reachability_limits() -> None:
    """The endpoint probe runs with 50-60 workers and a 300 ms deadline."""
    config = load_config(PROJECT_ROOT / "config.yaml")

    assert 50 <= config.reachability.workers <= 60
    assert config.reachability.workers == 56
    assert config.reachability.batch_size == 256
    assert config.reachability.timeout_ms == 300
