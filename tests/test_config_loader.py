from dataclasses import replace
from pathlib import Path

import pytest

from subscription_collector.config_loader import ConfigError, load_config, validate_config


def _write_config(path: Path, extra: str = "") -> None:
    path.write_text(
        """
paths:
  input: custom-input.txt
  output_dir: custom-output
  report: custom-report.json
  state: custom-state.json
sources:
  max_age_hours: 24
  concurrency: 12
  timeout_seconds: 15.0
  max_response_bytes: 1048576
  max_redirects: 2
  user_agent: collector-test/1.0
telegram:
  registry: tg_channels
  state: .collector/channel_state.json
  max_post_age_hours: 72
  concurrency: 4
  timeout_seconds: 15.0
  max_response_bytes: 2097152
  max_redirects: 2
  max_pages_per_channel: 8
  sample_post_limit: 25
channel_quality:
  approval_score: 55.0
  min_evidence_runs: 2
  min_supported_candidates: 2
  min_fresh_posts: 2
static_filter:
  workers: 6
  batch_size: 128
behavior:
  strict_first_seen: true
  fail_on_empty: false
""".lstrip()
        + extra,
        encoding="utf-8",
    )


def test_load_config_reads_all_runtime_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)

    config = load_config(config_path)

    assert config.paths.input_path == Path("custom-input.txt")
    assert config.paths.output_dir == Path("custom-output")
    assert config.paths.report_path == Path("custom-report.json")
    assert config.paths.state_path == Path("custom-state.json")
    assert config.sources.max_age_hours == 24
    assert config.sources.concurrency == 12
    assert config.sources.timeout_seconds == 15.0
    assert config.sources.max_response_bytes == 1_048_576
    assert config.sources.max_redirects == 2
    assert config.sources.user_agent == "collector-test/1.0"
    assert config.static_filter.workers == 6
    assert config.static_filter.batch_size == 128
    assert config.behavior.strict_first_seen is True
    assert config.behavior.fail_on_empty is False


def test_load_config_rejects_missing_or_invalid_required_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace("concurrency: 12", "concurrency: 0"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="sources.concurrency"):
        load_config(config_path)

    with pytest.raises(ConfigError, match="не найден"):
        load_config(tmp_path / "missing.yaml")


def test_validate_config_rejects_invalid_runtime_override(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    config = load_config(config_path)

    with pytest.raises(ConfigError, match="sources.concurrency"):
        validate_config(replace(config, sources=replace(config.sources, concurrency=0)))


def test_load_config_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, "\nsources:\n  concurrency: 1\n")

    with pytest.raises(ConfigError, match="повторяющийся ключ"):
        load_config(config_path)


def test_load_config_reads_telegram_and_channel_quality_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)

    config = load_config(config_path)

    assert config.telegram.registry_path == Path("tg_channels")
    assert config.telegram.max_post_age_hours == 72
    assert config.telegram.max_pages_per_channel == 8
    assert config.channel_quality.approval_score == 55.0
    assert config.channel_quality.min_evidence_runs == 2


def test_load_config_rejects_telegram_window_larger_than_72_hours(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "max_post_age_hours: 72", "max_post_age_hours: 73"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="telegram.max_post_age_hours"):
        load_config(config_path)


def test_config_schema_does_not_expose_xray_or_ip_validation(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)

    config = load_config(config_path)

    assert not hasattr(config.paths, "xray_path")
    assert not hasattr(config, "ip_validation")
    assert not hasattr(config, "xray")


@pytest.mark.parametrize("retired_section", ["ip_validation", "xray"])
def test_load_config_rejects_retired_xray_sections(tmp_path: Path, retired_section: str) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, f"\n{retired_section}: {{}}\n")

    with pytest.raises(ConfigError, match="неизвестные параметры"):
        load_config(config_path)
