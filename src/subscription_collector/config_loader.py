from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.YAMLError(f"повторяющийся ключ: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class ConfigError(ValueError):
    """Raised when config.yaml is absent, malformed, or contains invalid settings."""


@dataclass(frozen=True)
class PathsConfig:
    input_path: Path
    output_dir: Path
    report_path: Path
    state_path: Path
    xray_path: Path


@dataclass(frozen=True)
class SourcesConfig:
    max_age_hours: int
    concurrency: int
    timeout_seconds: float
    max_response_bytes: int
    max_redirects: int
    user_agent: str


@dataclass(frozen=True)
class TelegramConfig:
    registry_path: Path
    state_path: Path
    max_post_age_hours: int
    concurrency: int
    timeout_seconds: float
    max_response_bytes: int
    max_redirects: int
    max_pages_per_channel: int
    sample_post_limit: int


@dataclass(frozen=True)
class ChannelQualityConfig:
    approval_score: float
    min_evidence_runs: int
    min_supported_candidates: int
    min_fresh_posts: int


@dataclass(frozen=True)
class StaticFilterConfig:
    workers: int
    batch_size: int


@dataclass(frozen=True)
class IpValidationConfig:
    ip_echo_urls: tuple[str, ...]
    http_check_urls: tuple[str, ...]
    accepted_http_statuses: tuple[int, ...]
    timeout_seconds: float
    config_test_timeout_seconds: float
    startup_timeout_seconds: float
    request_concurrency: int
    batch_size: int
    batch_concurrency: int
    listener_poll_interval_seconds: float
    process_shutdown_timeout_seconds: float
    connection_max_connections: int
    connection_max_keepalive_connections: int


@dataclass(frozen=True)
class BehaviorConfig:
    strict_first_seen: bool
    fail_on_empty: bool


@dataclass(frozen=True)
class XrayConfig:
    version: str


@dataclass(frozen=True)
class CollectorConfig:
    paths: PathsConfig
    sources: SourcesConfig
    telegram: TelegramConfig
    channel_quality: ChannelQualityConfig
    static_filter: StaticFilterConfig
    ip_validation: IpValidationConfig
    behavior: BehaviorConfig
    xray: XrayConfig


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{location} должен быть YAML-словарём")
    return value


def _check_keys(section: dict[str, Any], location: str, expected: set[str]) -> None:
    actual = set(section)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        raise ConfigError(
            f"В {location} отсутствуют обязательные параметры: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise ConfigError(f"В {location} есть неизвестные параметры: {', '.join(sorted(unknown))}")


def _string(section: dict[str, Any], key: str, location: str) -> str:
    value = section[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location}.{key} должен быть непустой строкой")
    return value


def _integer(section: dict[str, Any], key: str, location: str, minimum: int) -> int:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{location}.{key} должен быть целым числом не меньше {minimum}")
    return value


def _number(section: dict[str, Any], key: str, location: str, minimum: float) -> float:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
        raise ConfigError(f"{location}.{key} должен быть числом не меньше {minimum}")
    return float(value)


def _boolean(section: dict[str, Any], key: str, location: str) -> bool:
    value = section[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{key} должен быть true или false")
    return value


def _https_url_value(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location} должен быть непустым HTTPS-адресом")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigError(f"{location} должен быть HTTPS-адресом")
    return value


def _https_urls(section: dict[str, Any], key: str, location: str) -> tuple[str, ...]:
    value = section[key]
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{location}.{key} должен быть непустым YAML-списком HTTPS-адресов")
    urls = tuple(_https_url_value(item, f"{location}.{key}") for item in value)
    if len(set(urls)) != len(urls):
        raise ConfigError(f"{location}.{key} не должен содержать повторяющиеся HTTPS-адреса")
    return urls


def _http_statuses(section: dict[str, Any], key: str, location: str) -> tuple[int, ...]:
    value = section[key]
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{location}.{key} должен быть непустым YAML-списком HTTP-кодов")
    statuses: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 100 <= item <= 599:
            raise ConfigError(f"{location}.{key} должен содержать HTTP-коды от 100 до 599")
        statuses.append(item)
    if len(set(statuses)) != len(statuses):
        raise ConfigError(f"{location}.{key} не должен содержать повторяющиеся HTTP-коды")
    return tuple(statuses)


def _paths_config(payload: dict[str, Any]) -> PathsConfig:
    section = _mapping(payload["paths"], "paths")
    _check_keys(section, "paths", {"input", "output_dir", "report", "state", "xray_path"})
    return PathsConfig(
        input_path=Path(_string(section, "input", "paths")),
        output_dir=Path(_string(section, "output_dir", "paths")),
        report_path=Path(_string(section, "report", "paths")),
        state_path=Path(_string(section, "state", "paths")),
        xray_path=Path(_string(section, "xray_path", "paths")),
    )


def _sources_config(payload: dict[str, Any]) -> SourcesConfig:
    section = _mapping(payload["sources"], "sources")
    _check_keys(
        section,
        "sources",
        {
            "max_age_hours",
            "concurrency",
            "timeout_seconds",
            "max_response_bytes",
            "max_redirects",
            "user_agent",
        },
    )
    return SourcesConfig(
        max_age_hours=_integer(section, "max_age_hours", "sources", 1),
        concurrency=_integer(section, "concurrency", "sources", 1),
        timeout_seconds=_number(section, "timeout_seconds", "sources", 0.000001),
        max_response_bytes=_integer(section, "max_response_bytes", "sources", 1),
        max_redirects=_integer(section, "max_redirects", "sources", 0),
        user_agent=_string(section, "user_agent", "sources"),
    )


def _telegram_config(payload: dict[str, Any]) -> TelegramConfig:
    section = _mapping(payload["telegram"], "telegram")
    _check_keys(
        section,
        "telegram",
        {
            "registry",
            "state",
            "max_post_age_hours",
            "concurrency",
            "timeout_seconds",
            "max_response_bytes",
            "max_redirects",
            "max_pages_per_channel",
            "sample_post_limit",
        },
    )
    max_post_age_hours = _integer(section, "max_post_age_hours", "telegram", 1)
    if max_post_age_hours > 72:
        raise ConfigError("telegram.max_post_age_hours должен быть не больше 72")
    return TelegramConfig(
        registry_path=Path(_string(section, "registry", "telegram")),
        state_path=Path(_string(section, "state", "telegram")),
        max_post_age_hours=max_post_age_hours,
        concurrency=_integer(section, "concurrency", "telegram", 1),
        timeout_seconds=_number(section, "timeout_seconds", "telegram", 0.000001),
        max_response_bytes=_integer(section, "max_response_bytes", "telegram", 1),
        max_redirects=_integer(section, "max_redirects", "telegram", 0),
        max_pages_per_channel=_integer(section, "max_pages_per_channel", "telegram", 1),
        sample_post_limit=_integer(section, "sample_post_limit", "telegram", 1),
    )


def _channel_quality_config(payload: dict[str, Any]) -> ChannelQualityConfig:
    section = _mapping(payload["channel_quality"], "channel_quality")
    _check_keys(
        section,
        "channel_quality",
        {
            "approval_score",
            "min_evidence_runs",
            "min_supported_candidates",
            "min_fresh_posts",
        },
    )
    approval_score = _number(section, "approval_score", "channel_quality", 0)
    if approval_score > 100:
        raise ConfigError("channel_quality.approval_score должен быть не больше 100")
    return ChannelQualityConfig(
        approval_score=approval_score,
        min_evidence_runs=_integer(section, "min_evidence_runs", "channel_quality", 1),
        min_supported_candidates=_integer(
            section, "min_supported_candidates", "channel_quality", 1
        ),
        min_fresh_posts=_integer(section, "min_fresh_posts", "channel_quality", 1),
    )


def _static_filter_config(payload: dict[str, Any]) -> StaticFilterConfig:
    section = _mapping(payload["static_filter"], "static_filter")
    _check_keys(section, "static_filter", {"workers", "batch_size"})
    return StaticFilterConfig(
        workers=_integer(section, "workers", "static_filter", 1),
        batch_size=_integer(section, "batch_size", "static_filter", 1),
    )


def _ip_validation_config(payload: dict[str, Any]) -> IpValidationConfig:
    section = _mapping(payload["ip_validation"], "ip_validation")
    _check_keys(
        section,
        "ip_validation",
        {
            "ip_echo_urls",
            "http_check_urls",
            "accepted_http_statuses",
            "timeout_seconds",
            "config_test_timeout_seconds",
            "startup_timeout_seconds",
            "request_concurrency",
            "batch_size",
            "batch_concurrency",
            "listener_poll_interval_seconds",
            "process_shutdown_timeout_seconds",
            "connection_max_connections",
            "connection_max_keepalive_connections",
        },
    )
    return IpValidationConfig(
        ip_echo_urls=_https_urls(section, "ip_echo_urls", "ip_validation"),
        http_check_urls=_https_urls(section, "http_check_urls", "ip_validation"),
        accepted_http_statuses=_http_statuses(section, "accepted_http_statuses", "ip_validation"),
        timeout_seconds=_number(section, "timeout_seconds", "ip_validation", 0.000001),
        config_test_timeout_seconds=_number(
            section, "config_test_timeout_seconds", "ip_validation", 0.000001
        ),
        startup_timeout_seconds=_number(
            section, "startup_timeout_seconds", "ip_validation", 0.000001
        ),
        request_concurrency=_integer(section, "request_concurrency", "ip_validation", 1),
        batch_size=_integer(section, "batch_size", "ip_validation", 1),
        batch_concurrency=_integer(section, "batch_concurrency", "ip_validation", 1),
        listener_poll_interval_seconds=_number(
            section, "listener_poll_interval_seconds", "ip_validation", 0.000001
        ),
        process_shutdown_timeout_seconds=_number(
            section, "process_shutdown_timeout_seconds", "ip_validation", 0.000001
        ),
        connection_max_connections=_integer(
            section, "connection_max_connections", "ip_validation", 1
        ),
        connection_max_keepalive_connections=_integer(
            section, "connection_max_keepalive_connections", "ip_validation", 0
        ),
    )


def _behavior_config(payload: dict[str, Any]) -> BehaviorConfig:
    section = _mapping(payload["behavior"], "behavior")
    _check_keys(section, "behavior", {"strict_first_seen", "fail_on_empty"})
    return BehaviorConfig(
        strict_first_seen=_boolean(section, "strict_first_seen", "behavior"),
        fail_on_empty=_boolean(section, "fail_on_empty", "behavior"),
    )


def _xray_config(payload: dict[str, Any]) -> XrayConfig:
    section = _mapping(payload["xray"], "xray")
    _check_keys(section, "xray", {"version"})
    return XrayConfig(version=_string(section, "version", "xray"))


def validate_config(config: CollectorConfig) -> CollectorConfig:
    """Validate a configuration object after temporary runtime overrides."""
    payload = {
        "paths": {
            "input": str(config.paths.input_path),
            "output_dir": str(config.paths.output_dir),
            "report": str(config.paths.report_path),
            "state": str(config.paths.state_path),
            "xray_path": str(config.paths.xray_path),
        },
        "sources": {
            "max_age_hours": config.sources.max_age_hours,
            "concurrency": config.sources.concurrency,
            "timeout_seconds": config.sources.timeout_seconds,
            "max_response_bytes": config.sources.max_response_bytes,
            "max_redirects": config.sources.max_redirects,
            "user_agent": config.sources.user_agent,
        },
        "telegram": {
            "registry": str(config.telegram.registry_path),
            "state": str(config.telegram.state_path),
            "max_post_age_hours": config.telegram.max_post_age_hours,
            "concurrency": config.telegram.concurrency,
            "timeout_seconds": config.telegram.timeout_seconds,
            "max_response_bytes": config.telegram.max_response_bytes,
            "max_redirects": config.telegram.max_redirects,
            "max_pages_per_channel": config.telegram.max_pages_per_channel,
            "sample_post_limit": config.telegram.sample_post_limit,
        },
        "channel_quality": {
            "approval_score": config.channel_quality.approval_score,
            "min_evidence_runs": config.channel_quality.min_evidence_runs,
            "min_supported_candidates": config.channel_quality.min_supported_candidates,
            "min_fresh_posts": config.channel_quality.min_fresh_posts,
        },
        "static_filter": {
            "workers": config.static_filter.workers,
            "batch_size": config.static_filter.batch_size,
        },
        "ip_validation": {
            "ip_echo_urls": list(config.ip_validation.ip_echo_urls),
            "http_check_urls": list(config.ip_validation.http_check_urls),
            "accepted_http_statuses": list(config.ip_validation.accepted_http_statuses),
            "timeout_seconds": config.ip_validation.timeout_seconds,
            "config_test_timeout_seconds": config.ip_validation.config_test_timeout_seconds,
            "startup_timeout_seconds": config.ip_validation.startup_timeout_seconds,
            "request_concurrency": config.ip_validation.request_concurrency,
            "batch_size": config.ip_validation.batch_size,
            "batch_concurrency": config.ip_validation.batch_concurrency,
            "listener_poll_interval_seconds": config.ip_validation.listener_poll_interval_seconds,
            "process_shutdown_timeout_seconds": (
                config.ip_validation.process_shutdown_timeout_seconds
            ),
            "connection_max_connections": config.ip_validation.connection_max_connections,
            "connection_max_keepalive_connections": (
                config.ip_validation.connection_max_keepalive_connections
            ),
        },
        "behavior": {
            "strict_first_seen": config.behavior.strict_first_seen,
            "fail_on_empty": config.behavior.fail_on_empty,
        },
        "xray": {"version": config.xray.version},
    }
    _paths_config(payload)
    _sources_config(payload)
    _telegram_config(payload)
    _channel_quality_config(payload)
    _static_filter_config(payload)
    _ip_validation_config(payload)
    _behavior_config(payload)
    _xray_config(payload)
    return config


def load_config(path: Path) -> CollectorConfig:
    """Load and validate the complete runtime configuration from one YAML file."""
    if not path.is_file():
        raise ConfigError(f"Файл конфигурации не найден: {path}")
    try:
        payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Не удалось прочитать {path}: {exc}") from exc
    root = _mapping(payload, "Корень config.yaml")
    _check_keys(
        root,
        "Корень config.yaml",
        {
            "paths",
            "sources",
            "telegram",
            "channel_quality",
            "static_filter",
            "ip_validation",
            "behavior",
            "xray",
        },
    )
    return validate_config(
        CollectorConfig(
            paths=_paths_config(root),
            sources=_sources_config(root),
            telegram=_telegram_config(root),
            channel_quality=_channel_quality_config(root),
            static_filter=_static_filter_config(root),
            ip_validation=_ip_validation_config(root),
            behavior=_behavior_config(root),
            xray=_xray_config(root),
        )
    )
