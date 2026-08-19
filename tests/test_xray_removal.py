from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_configuration_and_automation_keep_xray_validation() -> None:
    """Prevent accidentally removing the required common validation path."""
    source_root = PROJECT_ROOT / "src" / "subscription_collector"

    assert (source_root / "probe.py").is_file()
    assert (source_root / "xray_config.py").is_file()
    assert "xray" in (PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8").lower()
    workflow = (PROJECT_ROOT / ".github/workflows/Update secure subscriptions.yml").read_text(
        encoding="utf-8"
    )
    assert "xray" in workflow.lower()
