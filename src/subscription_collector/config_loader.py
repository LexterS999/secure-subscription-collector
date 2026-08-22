from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

import yaml

_T = TypeVar("_T")


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
class ChannelQualityConfig:
    """Adaptive public-channel quality model with bounded historical memory."""

    approval_score: float = 45.0
    min_evidence_runs: int = 2
    min_supported_candidates: int = 1
    min_fresh_posts: int = 1
    minimum_confidence: float = 0.3
    new_channel_margin: float = 8.0
    near_threshold_margin: float = 12.0
    history_half_life_hours: float = 72.0
    analysis_prior_passes: float = 1.0
    analysis_prior_failures: float = 1.0
    evidence_discount: float = 2.0
    discount_floor: float = 15.0
    momentum_cap: float = 5.0
    relative_approval: bool = True
    relative_floor: float = 10.0
    activity_weight: float = 15.0
    supported_yield_weight: float = 15.0
    static_security_weight: float = 20.0
    uniqueness_weight: float = 10.0
    nonduplication_weight: float = 5.0
    profile_coverage_weight: float = 10.0
    text_depth_weight: float = 5.0
    cadence_weight: float = 5.0
    depth_weight: float = 15.0


@dataclass(frozen=True)
class TelegramConfig:
    """Public preview collection limits shared by every fetched channel."""

    max_post_age_hours: int = 72
    max_profiles_per_channel: int | None = 1000
    max_pages_per_channel: int | None = None
    reevaluation_interval: int = 3
    concurrency: int = 12
    timeout_seconds: float = 20.0
    max_response_bytes: int = 5_242_880
    max_redirects: int = 3
    quality: ChannelQualityConfig = field(default_factory=ChannelQualityConfig)


@dataclass(frozen=True)
class ReachabilityConfig:
    """TCP endpoint probing limits applied before publication."""

    workers: int = 56
    batch_size: int = 256
    timeout_ms: int = 300


@dataclass(frozen=True)
class SpeedTestConfig:
    """Tunnel throughput gating applied to unique profiles before publication."""

    enabled: bool = True
    mode: str = "best_effort"
    min_kbps: float = 200.0
    download_bytes: int = 2_097_152
    max_duration_seconds: float = 8.0
    timeout_seconds: float = 12.0
    workers: int = 56
    batch_size: int = 128
    download_url: str = "http://cachefly.cachefly.net/5mb.test"


@dataclass(frozen=True)
class PathsConfig:
    input_path: Path
    output_dir: Path
    report_path: Path
    state_path: Path
    tg_channels_path: Path = Path("output/tg_channels.txt")
    telegram_state_path: Path = Path(".collector/channel_state.json")
    telegram_registry_path: Path = Path(".collector/tg_registry.txt")


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
class CollectorConfig:
    paths: PathsConfig
    sources: SourcesConfig
    static_filter: StaticFilterConfig
    behavior: BehaviorConfig
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    reachability: ReachabilityConfig = field(default_factory=ReachabilityConfig)
    speed_test: SpeedTestConfig = field(default_factory=SpeedTestConfig)


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{location} должен быть YAML-словарём")
    return value


def _check_keys(
    section: dict[str, Any], location: str, expected: set[str], optional: set[str] = frozenset()
) -> None:
    actual = set(section)
    missing = expected - actual
    unknown = actual - expected - set(optional)
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


def _optional_string(section: dict[str, Any], key: str, location: str) -> str | None:
    if key not in section or section[key] is None:
        return None
    value = section[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location}.{key} должен быть непустой строкой")
    return value


def _integer(section: dict[str, Any], key: str, location: str, minimum: int) -> int:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{location}.{key} должен быть целым числом не меньше {minimum}")
    return value


def _optional_integer(section: dict[str, Any], key: str, location: str, minimum: int) -> int | None:
    if key not in section or section[key] is None:
        return None
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{location}.{key} должен быть целым числом не меньше {minimum} или null")
    return value


def _number(section: dict[str, Any], key: str, location: str, minimum: float) -> float:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
        raise ConfigError(f"{location}.{key} должен быть числом не меньше {minimum}")
    return float(value)


def _optional_number(
    section: dict[str, Any],
    key: str,
    location: str,
    minimum: float,
    maximum: float | None = None,
) -> float | None:
    if key not in section or section[key] is None:
        return None
    value = section[key]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        bounds = f"от {minimum} до {maximum}" if maximum is not None else f"не меньше {minimum}"
        raise ConfigError(f"{location}.{key} должен быть числом {bounds}")
    return float(value)


def _boolean(section: dict[str, Any], key: str, location: str) -> bool:
    value = section[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{key} должен быть true или false")
    return value


def _optional_boolean(section: dict[str, Any], key: str, location: str) -> bool | None:
    if key not in section or section[key] is None:
        return None
    value = section[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{key} должен быть true или false")
    return value


def _or_default(value: _T | None, default: _T) -> _T:
    return default if value is None else value


def _https_url_value(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location} должен быть непустым HTTPS-адресом")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigError(f"{location} должен быть HTTPS-адресом")
    return value


_PATHS_OPTIONAL_KEYS = {"tg_channels", "telegram_state", "telegram_registry"}
_TELEGRAM_KEYS = {
    "max_post_age_hours",
    "max_profiles_per_channel",
    "max_pages_per_channel",
    "reevaluation_interval",
    "concurrency",
    "timeout_seconds",
    "max_response_bytes",
    "max_redirects",
    "quality",
}
_REACHABILITY_KEYS = {"workers", "batch_size", "timeout_ms"}
_CHANNEL_QUALITY_KEYS = {
    "approval_score",
    "min_evidence_runs",
    "min_supported_candidates",
    "min_fresh_posts",
    "minimum_confidence",
    "new_channel_margin",
    "near_threshold_margin",
    "history_half_life_hours",
    "analysis_prior_passes",
    "analysis_prior_failures",
    "evidence_discount",
    "discount_floor",
    "momentum_cap",
    "relative_approval",
    "relative_floor",
    "activity_weight",
    "supported_yield_weight",
    "static_security_weight",
    "uniqueness_weight",
    "nonduplication_weight",
    "profile_coverage_weight",
    "text_depth_weight",
    "cadence_weight",
    "depth_weight",
}


def _paths_config(payload: dict[str, Any]) -> PathsConfig:
    section = _mapping(payload["paths"], "paths")
    _check_keys(section, "paths", {"input", "output_dir", "report", "state"}, _PATHS_OPTIONAL_KEYS)
    return PathsConfig(
        input_path=Path(_string(section, "input", "paths")),
        output_dir=Path(_string(section, "output_dir", "paths")),
        report_path=Path(_string(section, "report", "paths")),
        state_path=Path(_string(section, "state", "paths")),
        tg_channels_path=Path(
            _or_default(_optional_string(section, "tg_channels", "paths"), "output/tg_channels.txt")
        ),
        telegram_state_path=Path(
            _or_default(
                _optional_string(section, "telegram_state", "paths"),
                ".collector/channel_state.json",
            )
        ),
        telegram_registry_path=Path(
            _or_default(
                _optional_string(section, "telegram_registry", "paths"),
                ".collector/tg_registry.txt",
            )
        ),
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


def _telegram_quality_config(payload: Any) -> ChannelQualityConfig:
    if payload is None:
        return ChannelQualityConfig()
    section = _mapping(payload, "telegram.quality")
    _check_keys(section, "telegram.quality", set(), _CHANNEL_QUALITY_KEYS)

    def bounded(key: str, default: float, minimum: float, maximum: float | None = None) -> float:
        return _or_default(
            _optional_number(section, key, "telegram.quality", minimum, maximum), default
        )

    return ChannelQualityConfig(
        approval_score=bounded("approval_score", 45.0, 0.0, 100.0),
        min_evidence_runs=_or_default(
            _optional_integer(section, "min_evidence_runs", "telegram.quality", 1), 2
        ),
        min_supported_candidates=_or_default(
            _optional_integer(section, "min_supported_candidates", "telegram.quality", 0), 1
        ),
        min_fresh_posts=_or_default(
            _optional_integer(section, "min_fresh_posts", "telegram.quality", 0), 1
        ),
        minimum_confidence=bounded("minimum_confidence", 0.3, 0.0, 1.0),
        new_channel_margin=bounded("new_channel_margin", 8.0, 0.0),
        near_threshold_margin=bounded("near_threshold_margin", 12.0, 0.0),
        history_half_life_hours=bounded("history_half_life_hours", 72.0, 0.000001),
        analysis_prior_passes=bounded("analysis_prior_passes", 1.0, 0.0),
        analysis_prior_failures=bounded("analysis_prior_failures", 1.0, 0.0),
        evidence_discount=bounded("evidence_discount", 2.0, 0.0),
        discount_floor=bounded("discount_floor", 15.0, 0.0),
        momentum_cap=bounded("momentum_cap", 5.0, 0.0),
        relative_approval=_or_default(
            _optional_boolean(section, "relative_approval", "telegram.quality"), True
        ),
        relative_floor=bounded("relative_floor", 10.0, 0.0),
        activity_weight=bounded("activity_weight", 15.0, 0.0),
        supported_yield_weight=bounded("supported_yield_weight", 15.0, 0.0),
        static_security_weight=bounded("static_security_weight", 20.0, 0.0),
        uniqueness_weight=bounded("uniqueness_weight", 10.0, 0.0),
        nonduplication_weight=bounded("nonduplication_weight", 5.0, 0.0),
        profile_coverage_weight=bounded("profile_coverage_weight", 10.0, 0.0),
        text_depth_weight=bounded("text_depth_weight", 5.0, 0.0),
        cadence_weight=bounded("cadence_weight", 5.0, 0.0),
        depth_weight=bounded("depth_weight", 15.0, 0.0),
    )


def _telegram_config(payload: Any) -> TelegramConfig:
    if payload is None:
        return TelegramConfig()
    section = _mapping(payload, "telegram")
    _check_keys(section, "telegram", set(), _TELEGRAM_KEYS)
    max_post_age_hours = _or_default(
        _optional_integer(section, "max_post_age_hours", "telegram", 1),
        72,
    )
    if max_post_age_hours > 72:
        raise ConfigError("telegram.max_post_age_hours должен быть целым числом от 1 до 72")
    return TelegramConfig(
        max_post_age_hours=max_post_age_hours,
        max_profiles_per_channel=_or_default(
            _optional_integer(section, "max_profiles_per_channel", "telegram", 1),
            1000,
        ),
        max_pages_per_channel=_optional_integer(section, "max_pages_per_channel", "telegram", 1),
        reevaluation_interval=_or_default(
            _optional_integer(section, "reevaluation_interval", "telegram", 1), 3
        ),
        concurrency=_or_default(_optional_integer(section, "concurrency", "telegram", 1), 12),
        timeout_seconds=_or_default(
            _optional_number(section, "timeout_seconds", "telegram", 0.000001), 20.0
        ),
        max_response_bytes=_or_default(
            _optional_integer(section, "max_response_bytes", "telegram", 1), 5_242_880
        ),
        max_redirects=_or_default(_optional_integer(section, "max_redirects", "telegram", 0), 3),
        quality=_telegram_quality_config(section.get("quality")),
    )


def _reachability_config(payload: Any) -> ReachabilityConfig:
    if payload is None:
        return ReachabilityConfig()
    section = _mapping(payload, "reachability")
    _check_keys(section, "reachability", set(), _REACHABILITY_KEYS)
    workers = _or_default(_optional_integer(section, "workers", "reachability", 1), 56)
    if not 50 <= workers <= 60:
        raise ConfigError("reachability.workers должен быть целым числом от 50 до 60")
    timeout_ms = _or_default(_optional_integer(section, "timeout_ms", "reachability", 1), 300)
    if timeout_ms > 300:
        raise ConfigError("reachability.timeout_ms должен быть целым числом от 1 до 300")
    return ReachabilityConfig(
        workers=workers,
        batch_size=_or_default(_optional_integer(section, "batch_size", "reachability", 1), 256),
        timeout_ms=timeout_ms,
    )


_SPEED_TEST_MODES = {"strict", "best_effort"}
_SPEED_TEST_KEYS = {
    "enabled",
    "mode",
    "min_kbps",
    "download_bytes",
    "max_duration_seconds",
    "timeout_seconds",
    "workers",
    "batch_size",
    "download_url",
}


def _speed_test_config(payload: Any) -> SpeedTestConfig:
    if payload is None:
        return SpeedTestConfig()
    section = _mapping(payload, "speed_test")
    _check_keys(section, "speed_test", set(), _SPEED_TEST_KEYS)
    mode = _or_default(_optional_string(section, "mode", "speed_test"), "best_effort")
    if mode not in _SPEED_TEST_MODES:
        raise ConfigError("speed_test.mode должен быть strict или best_effort")
    download_url = _or_default(
        _optional_string(section, "download_url", "speed_test"),
        "http://cachefly.cachefly.net/5mb.test",
    )
    parsed_url = urlsplit(download_url)
    if parsed_url.scheme != "http" or not parsed_url.netloc or parsed_url.path in {"", "/"}:
        raise ConfigError(
            "speed_test.download_url должен быть полным HTTP-адресом загружаемого файла"
        )
    workers = _or_default(_optional_integer(section, "workers", "speed_test", 1), 56)
    if not 50 <= workers <= 60:
        raise ConfigError("speed_test.workers должен быть целым числом от 50 до 60")
    return SpeedTestConfig(
        enabled=_or_default(_optional_boolean(section, "enabled", "speed_test"), True),
        mode=mode,
        min_kbps=_or_default(_optional_number(section, "min_kbps", "speed_test", 1.0), 200.0),
        download_bytes=_or_default(
            _optional_integer(section, "download_bytes", "speed_test", 262_144), 2_097_152
        ),
        max_duration_seconds=_or_default(
            _optional_number(section, "max_duration_seconds", "speed_test", 1.0), 8.0
        ),
        timeout_seconds=_or_default(
            _optional_number(section, "timeout_seconds", "speed_test", 1.0), 12.0
        ),
        workers=workers,
        batch_size=_or_default(_optional_integer(section, "batch_size", "speed_test", 1), 128),
        download_url=download_url,
    )


def validate_config(config: CollectorConfig) -> CollectorConfig:
    """Validate a configuration object after temporary runtime overrides."""
    payload = {
        "paths": {
            "input": str(config.paths.input_path),
            "output_dir": str(config.paths.output_dir),
            "report": str(config.paths.report_path),
            "state": str(config.paths.state_path),
            "tg_channels": str(config.paths.tg_channels_path),
            "telegram_state": str(config.paths.telegram_state_path),
            "telegram_registry": str(config.paths.telegram_registry_path),
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
            "reevaluation_interval": config.telegram.reevaluation_interval,
            "concurrency": config.telegram.concurrency,
            "timeout_seconds": config.telegram.timeout_seconds,
            "max_response_bytes": config.telegram.max_response_bytes,
            "max_redirects": config.telegram.max_redirects,
            "quality": {
                "approval_score": config.telegram.quality.approval_score,
                "min_evidence_runs": config.telegram.quality.min_evidence_runs,
                "min_supported_candidates": config.telegram.quality.min_supported_candidates,
                "min_fresh_posts": config.telegram.quality.min_fresh_posts,
                "minimum_confidence": config.telegram.quality.minimum_confidence,
                "new_channel_margin": config.telegram.quality.new_channel_margin,
                "near_threshold_margin": config.telegram.quality.near_threshold_margin,
                "history_half_life_hours": config.telegram.quality.history_half_life_hours,
                "analysis_prior_passes": config.telegram.quality.analysis_prior_passes,
                "analysis_prior_failures": config.telegram.quality.analysis_prior_failures,
                "evidence_discount": config.telegram.quality.evidence_discount,
                "discount_floor": config.telegram.quality.discount_floor,
                "momentum_cap": config.telegram.quality.momentum_cap,
                "relative_approval": config.telegram.quality.relative_approval,
                "relative_floor": config.telegram.quality.relative_floor,
                "activity_weight": config.telegram.quality.activity_weight,
                "supported_yield_weight": config.telegram.quality.supported_yield_weight,
                "static_security_weight": config.telegram.quality.static_security_weight,
                "uniqueness_weight": config.telegram.quality.uniqueness_weight,
                "nonduplication_weight": config.telegram.quality.nonduplication_weight,
                "profile_coverage_weight": config.telegram.quality.profile_coverage_weight,
                "text_depth_weight": config.telegram.quality.text_depth_weight,
                "cadence_weight": config.telegram.quality.cadence_weight,
                "depth_weight": config.telegram.quality.depth_weight,
            },
        },
        "reachability": {
            "workers": config.reachability.workers,
            "batch_size": config.reachability.batch_size,
            "timeout_ms": config.reachability.timeout_ms,
        },
        "speed_test": {
            "enabled": config.speed_test.enabled,
            "mode": config.speed_test.mode,
            "min_kbps": config.speed_test.min_kbps,
            "download_bytes": config.speed_test.download_bytes,
            "max_duration_seconds": config.speed_test.max_duration_seconds,
            "timeout_seconds": config.speed_test.timeout_seconds,
            "workers": config.speed_test.workers,
            "batch_size": config.speed_test.batch_size,
            "download_url": config.speed_test.download_url,
        },
    }
    _paths_config(payload)
    _sources_config(payload)
    _static_filter_config(payload)
    _behavior_config(payload)
    _telegram_config(payload["telegram"])
    _reachability_config(payload["reachability"])
    _speed_test_config(payload["speed_test"])
    return config


def load_config(path: Path | str) -> CollectorConfig:
    """Load and validate the complete runtime configuration from one YAML file."""
    path = Path(path)
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
        {"paths", "sources", "static_filter", "behavior"},
        {"telegram", "reachability", "speed_test"},
    )
    return validate_config(
        CollectorConfig(
            paths=_paths_config(root),
            sources=_sources_config(root),
            static_filter=_static_filter_config(root),
            behavior=_behavior_config(root),
            telegram=_telegram_config(root.get("telegram")),
            reachability=_reachability_config(root.get("reachability")),
            speed_test=_speed_test_config(root.get("speed_test")),
        )
    )
