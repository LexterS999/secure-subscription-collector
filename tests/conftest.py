from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from subscription_collector import cli
from subscription_collector.config_loader import CollectorConfig, load_config
from subscription_collector.reachability import EndpointProbe
from subscription_collector.speedtest import SpeedOutcome

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def responsive_endpoints(monkeypatch: pytest.MonkeyPatch):
    """Keep pipeline tests offline: every probed endpoint pretends to respond."""

    async def fake_probe(endpoints, settings):
        return {
            endpoint: EndpointProbe(
                endpoint.host,
                endpoint.port,
                endpoint.use_tls,
                endpoint.server_name,
                True,
                "tcp",
                25,
            )
            for endpoint in endpoints
        }

    monkeypatch.setattr(cli, "probe_endpoints", fake_probe)


@pytest.fixture(autouse=True)
def fast_speed_tests(monkeypatch: pytest.MonkeyPatch):
    """Keep pipeline tests offline: every measured profile pretends to be fast."""

    async def fake_speed_tests(profiles, settings, latency_components=None):
        return {id(profile): SpeedOutcome(True, kbps=9999.0) for profile in profiles}

    monkeypatch.setattr(cli, "run_speed_tests", fake_speed_tests)


@pytest.fixture
def config_for(tmp_path: Path):
    def build(
        *,
        input_path: Path | None = None,
        output_dir: Path | None = None,
        report_path: Path | None = None,
        state_path: Path | None = None,
        tg_channels_path: Path | None = None,
        telegram_state_path: Path | None = None,
        telegram_registry_path: Path | None = None,
    ) -> CollectorConfig:
        config = load_config(PROJECT_ROOT / "config.yaml")
        return replace(
            config,
            paths=replace(
                config.paths,
                input_path=input_path or tmp_path / "input.txt",
                output_dir=output_dir or tmp_path / "output",
                report_path=report_path or tmp_path / "report.json",
                state_path=state_path or tmp_path / "state.json",
                tg_channels_path=tg_channels_path or tmp_path / "tg_channels.txt",
                telegram_state_path=telegram_state_path or tmp_path / "channel_state.json",
                telegram_registry_path=telegram_registry_path or tmp_path / "tg_registry.txt",
                profile_pool_path=tmp_path / "profile_pool.json",
            ),
        )

    return build
