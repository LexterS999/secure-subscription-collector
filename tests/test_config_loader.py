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
  xray_path: /opt/xray/xray
sources:
  max_age_hours: 24
  concurrency: 12
  timeout_seconds: 15.0
  max_response_bytes: 1048576
  max_redirects: 2
  user_agent: collector-test/1.0
static_filter:
  workers: 6
  batch_size: 128
ip_validation:
  ip_echo_urls:
    - https://ifconfig.example/ip
    - https://ip.example/address
  http_check_urls:
    - https://status.example/generate_204
  accepted_http_statuses: [200, 204, 301, 302, 307]
  timeout_seconds: 1.25
  config_test_timeout_seconds: 10.0
  startup_timeout_seconds: 2.5
  request_concurrency: 16
  batch_size: 64
  batch_concurrency: 3
  listener_poll_interval_seconds: 0.05
  process_shutdown_timeout_seconds: 0.3
  connection_max_connections: 2
  connection_max_keepalive_connections: 1
behavior:
  strict_first_seen: true
  fail_on_empty: false
xray:
  version: v26.3.27
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
    assert config.paths.xray_path == Path("/opt/xray/xray")
    assert config.sources.max_age_hours == 24
    assert config.sources.concurrency == 12
    assert config.sources.timeout_seconds == 15.0
    assert config.sources.max_response_bytes == 1_048_576
    assert config.sources.max_redirects == 2
    assert config.sources.user_agent == "collector-test/1.0"
    assert config.static_filter.workers == 6
    assert config.static_filter.batch_size == 128
    assert config.ip_validation.ip_echo_urls == (
        "https://ifconfig.example/ip",
        "https://ip.example/address",
    )
    assert config.ip_validation.http_check_urls == ("https://status.example/generate_204",)
    assert config.ip_validation.accepted_http_statuses == (200, 204, 301, 302, 307)
    assert config.ip_validation.timeout_seconds == 1.25
    assert config.ip_validation.config_test_timeout_seconds == 10.0
    assert config.ip_validation.startup_timeout_seconds == 2.5
    assert config.ip_validation.request_concurrency == 16
    assert config.ip_validation.batch_size == 64
    assert config.ip_validation.batch_concurrency == 3
    assert config.ip_validation.listener_poll_interval_seconds == 0.05
    assert config.ip_validation.process_shutdown_timeout_seconds == 0.3
    assert config.ip_validation.connection_max_connections == 2
    assert config.ip_validation.connection_max_keepalive_connections == 1
    assert config.behavior.strict_first_seen is True
    assert config.behavior.fail_on_empty is False
    assert config.xray.version == "v26.3.27"


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
