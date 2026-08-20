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
    telegram_state_path: Path
    telegram_registry_path: Path
    tg_channels_path: Path


@dataclass(frozen=True)
class SourcesConfig:
    max_age_hours: int
    concurrency: int
    timeout_seconds: float
    max_response_bytes: int
    max_redirects: int
    user_agent: str


@dataclass(frozen=True)
class StaticFilterConfig:
    workers: int
    batch_size: int


@dataclass(frozen=True)
class BehaviorConfig:
    strict_first_seen: bool
    fail_on_empty: bool


@dataclass(frozen=True)
class ChannelQualityConfig:
    approval_score: float
    min_evidence_runs: int
    min_supported_candidates: int
    min_fresh_posts: int
    new_channel_margin: float = 20.0
    minimum_confidence: float = 0.5
    history_half_life_hours: float = 72.0
    activity_weight: float = 20.0
    supported_yield_weight: float = 20.0
    static_security_weight: float = 25.0
    uniqueness_weight: float = 15.0
    nonduplication_weight: float = 10.0
    profile_coverage_weight: float = 10.0
    text_depth_weight: float = 5.0
    cadence_weight: float = 5.0
    history_weight: float = 15.0
    near_threshold_margin: float = 8.0


@dataclass(frozen=True)
class TelegramConfig:
    max_post_age_hours: int
    max_profiles_per_channel: int | None
    max_pages_per_channel: int | None
    concurrency: int
    timeout_seconds: float
    max_response_bytes: int
    max_redirects: int
    quality: ChannelQualityConfig


@dataclass(frozen=True)
class CollectorConfig:
    paths: PathsConfig
    sources: SourcesConfig
    static_filter: StaticFilterConfig
    behavior: BehaviorConfig
    telegram: TelegramConfig


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
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise ConfigError(f"{location} должен быть HTTPS-адресом") from error
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
    _check_keys(
        section,
        "paths",
        {
            "input",
            "output_dir",
            "report",
            "state",
            "telegram_state",
            "telegram_registry",
            "tg_channels",
        },
    )
    return PathsConfig(
        input_path=Path(_string(section, "input", "paths")),
        output_dir=Path(_string(section, "output_dir", "paths")),
        report_path=Path(_string(section, "report", "paths")),
        state_path=Path(_string(section, "state", "paths")),
        telegram_state_path=Path(_string(section, "telegram_state", "paths")),
        telegram_registry_path=Path(_string(section, "telegram_registry", "paths")),
        tg_channels_path=Path(_string(section, "tg_channels", "paths")),
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


def _static_filter_config(payload: dict[str, Any]) -> StaticFilterConfig:
    section = _mapping(payload["static_filter"], "static_filter")
    _check_keys(section, "static_filter", {"workers", "batch_size"})
    return StaticFilterConfig(
        workers=_integer(section, "workers", "static_filter", 1),
        batch_size=_integer(section, "batch_size", "static_filter", 1),
    )


def _behavior_config(payload: dict[str, Any]) -> BehaviorConfig:
    section = _mapping(payload["behavior"], "behavior")
    _check_keys(section, "behavior", {"strict_first_seen", "fail_on_empty"})
    return BehaviorConfig(
        strict_first_seen=_boolean(section, "strict_first_seen", "behavior"),
        fail_on_empty=_boolean(section, "fail_on_empty", "behavior"),
    )


def _quality_config(value: Any) -> ChannelQualityConfig:
    section = _mapping(value, "telegram.quality")
    _check_keys(
        section,
        "telegram.quality",
        {
            "approval_score",
            "min_evidence_runs",
            "min_supported_candidates",
            "min_fresh_posts",
            "new_channel_margin",
            "minimum_confidence",
            "history_half_life_hours",
            "activity_weight",
            "supported_yield_weight",
            "static_security_weight",
            "uniqueness_weight",
            "nonduplication_weight",
            "profile_coverage_weight",
            "text_depth_weight",
            "cadence_weight",
            "history_weight",
            "near_threshold_margin",
        },
    )

    def bounded(key: str, minimum: float, maximum: float) -> float:
        parsed = _number(section, key, "telegram.quality", minimum)
        if parsed > maximum:
            raise ConfigError(f"telegram.quality.{key} должен быть числом не больше {maximum}")
        return parsed

    return ChannelQualityConfig(
        approval_score=bounded("approval_score", 0.0, 100.0),
        min_evidence_runs=_integer(section, "min_evidence_runs", "telegram.quality", 1),
        min_supported_candidates=_integer(
            section, "min_supported_candidates", "telegram.quality", 1
        ),
        min_fresh_posts=_integer(section, "min_fresh_posts", "telegram.quality", 1),
        new_channel_margin=bounded("new_channel_margin", 0.0, 100.0),
        minimum_confidence=bounded("minimum_confidence", 0.0, 1.0),
        history_half_life_hours=_number(
            section, "history_half_life_hours", "telegram.quality", 0.000001
        ),
        activity_weight=_number(section, "activity_weight", "telegram.quality", 0.0),
        supported_yield_weight=_number(section, "supported_yield_weight", "telegram.quality", 0.0),
        static_security_weight=_number(section, "static_security_weight", "telegram.quality", 0.0),
        uniqueness_weight=_number(section, "uniqueness_weight", "telegram.quality", 0.0),
        nonduplication_weight=_number(section, "nonduplication_weight", "telegram.quality", 0.0),
        profile_coverage_weight=_number(
            section, "profile_coverage_weight", "telegram.quality", 0.0
        ),
        text_depth_weight=_number(section, "text_depth_weight", "telegram.quality", 0.0),
        cadence_weight=_number(section, "cadence_weight", "telegram.quality", 0.0),
        history_weight=_number(section, "history_weight", "telegram.quality", 0.0),
        near_threshold_margin=bounded("near_threshold_margin", 0.0, 100.0),
    )


def _telegram_config(payload: dict[str, Any]) -> TelegramConfig:
    section = _mapping(payload["telegram"], "telegram")
    _check_keys(
        section,
        "telegram",
        {
            "max_post_age_hours",
            "max_profiles_per_channel",
            "max_pages_per_channel",
            "concurrency",
            "timeout_seconds",
            "max_response_bytes",
            "max_redirects",
            "quality",
        },
    )
    max_profiles = section["max_profiles_per_channel"]
    max_pages = section["max_pages_per_channel"]
    if max_profiles is not None:
        raise ConfigError("telegram.max_profiles_per_channel должен быть null")
    if max_pages is not None:
        raise ConfigError("telegram.max_pages_per_channel должен быть null")
    return TelegramConfig(
        max_post_age_hours=_integer(section, "max_post_age_hours", "telegram", 1),
        max_profiles_per_channel=None,
        max_pages_per_channel=None,
        concurrency=_integer(section, "concurrency", "telegram", 1),
        timeout_seconds=_number(section, "timeout_seconds", "telegram", 0.000001),
        max_response_bytes=_integer(section, "max_response_bytes", "telegram", 1),
        max_redirects=_integer(section, "max_redirects", "telegram", 0),
        quality=_quality_config(section["quality"]),
    )


def validate_config(config: CollectorConfig) -> CollectorConfig:
    """Validate a configuration object after temporary runtime overrides."""
    payload = {
        "paths": {
            "input": str(config.paths.input_path),
            "output_dir": str(config.paths.output_dir),
            "report": str(config.paths.report_path),
            "state": str(config.paths.state_path),
            "telegram_state": str(config.paths.telegram_state_path),
            "telegram_registry": str(config.paths.telegram_registry_path),
            "tg_channels": str(config.paths.tg_channels_path),
        },
        "sources": {
            "max_age_hours": config.sources.max_age_hours,
            "concurrency": config.sources.concurrency,
            "timeout_seconds": config.sources.timeout_seconds,
            "max_response_bytes": config.sources.max_response_bytes,
            "max_redirects": config.sources.max_redirects,
            "user_agent": config.sources.user_agent,
        },
        "static_filter": {
            "workers": config.static_filter.workers,
            "batch_size": config.static_filter.batch_size,
        },
        "behavior": {
            "strict_first_seen": config.behavior.strict_first_seen,
            "fail_on_empty": config.behavior.fail_on_empty,
        },
        "telegram": {
            "max_post_age_hours": config.telegram.max_post_age_hours,
            "max_profiles_per_channel": config.telegram.max_profiles_per_channel,
            "max_pages_per_channel": config.telegram.max_pages_per_channel,
            "concurrency": config.telegram.concurrency,
            "timeout_seconds": config.telegram.timeout_seconds,
            "max_response_bytes": config.telegram.max_response_bytes,
            "max_redirects": config.telegram.max_redirects,
            "quality": {
                "approval_score": config.telegram.quality.approval_score,
                "min_evidence_runs": config.telegram.quality.min_evidence_runs,
                "min_supported_candidates": config.telegram.quality.min_supported_candidates,
                "min_fresh_posts": config.telegram.quality.min_fresh_posts,
                "new_channel_margin": config.telegram.quality.new_channel_margin,
                "minimum_confidence": config.telegram.quality.minimum_confidence,
                "history_half_life_hours": config.telegram.quality.history_half_life_hours,
                "activity_weight": config.telegram.quality.activity_weight,
                "supported_yield_weight": config.telegram.quality.supported_yield_weight,
                "static_security_weight": config.telegram.quality.static_security_weight,
                "uniqueness_weight": config.telegram.quality.uniqueness_weight,
                "nonduplication_weight": config.telegram.quality.nonduplication_weight,
                "profile_coverage_weight": config.telegram.quality.profile_coverage_weight,
                "text_depth_weight": config.telegram.quality.text_depth_weight,
                "cadence_weight": config.telegram.quality.cadence_weight,
                "history_weight": config.telegram.quality.history_weight,
                "near_threshold_margin": config.telegram.quality.near_threshold_margin,
            },
        },
    }
    _paths_config(payload)
    _sources_config(payload)
    _static_filter_config(payload)
    _behavior_config(payload)
    _telegram_config(payload)
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
        {"paths", "sources", "static_filter", "behavior", "telegram"},
    )
    return validate_config(
        CollectorConfig(
            paths=_paths_config(root),
            sources=_sources_config(root),
            static_filter=_static_filter_config(root),
            behavior=_behavior_config(root),
            telegram=_telegram_config(root),
        )
    )
