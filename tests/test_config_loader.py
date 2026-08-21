from pathlib import Path

import pytest
import yaml

from subscription_collector.config_loader import (
    CollectorConfig,
    ConfigError,
    load_config,
    validate_config,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _write_config(tmp_path: Path, payload: dict) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return config_path


@pytest.fixture
def base_payload() -> dict:
    return {
        "paths": {
            "input": "input.txt",
            "output_dir": "output",
            "report": "report.json",
            "state": ".collector/state.json",
        },
        "sources": {
            "max_age_hours": 72,
            "concurrency": 48,
            "timeout_seconds": 20.0,
            "max_response_bytes": 5242880,
            "max_redirects": 3,
            "user_agent": "secure-subscription-collector/0.1",
        },
        "static_filter": {"workers": 160, "batch_size": 1024},
        "behavior": {"strict_first_seen": False, "fail_on_empty": False},
    }


def test_load_config_parses_full_document(base_payload: dict, tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, base_payload))

    assert config.paths.input_path == Path("input.txt")
    assert config.paths.output_dir == Path("output")
    assert config.sources.max_age_hours == 72
    assert config.static_filter.workers == 160
    assert config.behavior.strict_first_seen is False


def test_load_config_applies_documented_defaults_for_optional_paths(
    base_payload: dict, tmp_path: Path
) -> None:
    config = load_config(_write_config(tmp_path, base_payload))

    assert config.paths.tg_channels_path == Path("output/tg_channels.txt")
    assert config.paths.telegram_state_path == Path(".collector/channel_state.json")
    assert config.paths.telegram_registry_path == Path(".collector/tg_registry.txt")


def test_load_config_rejects_duplicate_keys(base_payload: dict, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    lines = [
        "paths:",
        "  input: input.txt",
        "  output_dir: output",
        "  report: report.json",
        "  state: .collector/state.json",
        "sources:",
        "  max_age_hours: 72",
        "  concurrency: 48",
        "  timeout_seconds: 20.0",
        "  max_response_bytes: 5242880",
        "  max_redirects: 3",
        "  user_agent: secure-subscription-collector/0.1",
        "static_filter:",
        "  workers: 160",
        "  batch_size: 1024",
        "behavior:",
        "  strict_first_seen: false",
        "  fail_on_empty: false",
        "telegram:",
        "  max_post_age_hours: 72",
        "  max_post_age_hours: 48",
    ]
    config_path.write_text("\n".join(lines), encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_validate_config_rejects_invalid_override(base_payload: dict, tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, base_payload))
    broken = CollectorConfig(
        paths=config.paths,
        sources=type(config.sources)(**{**config.sources.__dict__, "concurrency": 0}),
        static_filter=config.static_filter,
        behavior=config.behavior,
    )

    with pytest.raises(ConfigError):
        validate_config(broken)


def test_missing_config_file_raises_actionable_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="не найден"):
        load_config(tmp_path / "missing.yaml")
