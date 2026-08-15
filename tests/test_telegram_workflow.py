from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_collection_workflow_commits_channel_registry_and_redacted_state() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/Update secure subscriptions.yml").read_text(
        encoding="utf-8"
    )

    assert "tg_channels" in workflow
    assert ".collector/channel_state.json" in workflow
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow


def test_readme_describes_public_preview_candidate_gate_and_output_invariant() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "t.me/s/" in readme
    assert "candidate" in readme
    assert "tg_channels" in readme
    assert "72" in readme
