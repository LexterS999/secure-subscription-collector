from pathlib import Path

from subscription_collector.config_loader import load_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_default_config_exposes_public_preview_window_without_profile_limit() -> None:
    """Prevent removing the required 24-hour Telegram collection window or adding a cap."""
    config = load_config(PROJECT_ROOT / "config.yaml")

    assert config.paths.tg_channels_path == Path("tg_channels.txt")
    assert config.paths.telegram_state_path == Path(".collector/channel_state.json")
    assert config.paths.telegram_registry_path == Path(".collector/tg_registry.txt")
    assert config.telegram.max_post_age_hours == 24
    assert config.telegram.max_profiles_per_channel is None
    assert config.telegram.max_pages_per_channel is None
    assert config.telegram.concurrency == 12
    assert config.telegram.timeout_seconds == 20.0
    assert config.telegram.max_response_bytes == 5_242_880
    assert config.telegram.max_redirects == 3
    assert config.telegram.quality.approval_score == 70.0
    assert config.telegram.quality.new_channel_margin == 20.0
    assert config.telegram.quality.minimum_confidence == 0.5
    assert config.telegram.quality.history_half_life_hours == 72.0
    assert config.telegram.quality.xray_prior_successes == 1.0
    assert config.telegram.quality.xray_prior_failures == 1.0
    assert config.telegram.quality.profile_coverage_weight == 10.0
    assert config.telegram.quality.text_depth_weight == 5.0
    assert config.telegram.quality.cadence_weight == 5.0
    assert config.telegram.quality.history_weight == 15.0
    assert config.telegram.quality.near_threshold_margin == 8.0
