from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from subscription_collector.config_loader import CollectorConfig, load_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config_for(tmp_path: Path):
    def build(
        *,
        input_path: Path | None = None,
        output_dir: Path | None = None,
        report_path: Path | None = None,
        state_path: Path | None = None,
        xray_path: Path | None = None,
        telegram_state_path: Path | None = None,
        telegram_registry_path: Path | None = None,
        tg_channels_path: Path | None = None,
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
                xray_path=xray_path or tmp_path / "xray",
                telegram_state_path=telegram_state_path or tmp_path / "channel_state.json",
                telegram_registry_path=telegram_registry_path or tmp_path / "tg_registry.txt",
                tg_channels_path=tg_channels_path or tmp_path / "tg_channels.txt",
            ),
        )

    return build
