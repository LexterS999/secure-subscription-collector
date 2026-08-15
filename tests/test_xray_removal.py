from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_configuration_and_automation_do_not_depend_on_xray() -> None:
    source_root = PROJECT_ROOT / "src" / "subscription_collector"

    assert not (source_root / "probe.py").exists()
    assert not (source_root / "xray_config.py").exists()
    assert "xray" not in (PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8").lower()
    workflow = (PROJECT_ROOT / ".github/workflows/Update secure subscriptions.yml").read_text(
        encoding="utf-8"
    )
    assert "xray" not in workflow.lower()
