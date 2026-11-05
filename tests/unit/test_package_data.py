"""The data the tool needs ships with the package, and the release checks the version."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_data_files_are_importable_resources() -> None:
    for package, name in (
        ("ifinjected.inventory", "catalog.json"),
        ("ifinjected.agents", "data.json"),
        ("ifinjected.trifecta", "mcp_catalog.json"),
    ):
        assert files(package).joinpath(name).read_text(encoding="utf-8").startswith("{")


def test_the_release_workflow_publishes_through_trusted_publishing() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "id-token: write" in workflow
    assert "https://pypi.org/project/ifinjected/" in workflow
    assert "tag_name" in workflow
    assert "password" not in workflow  # no API token is stored anywhere
