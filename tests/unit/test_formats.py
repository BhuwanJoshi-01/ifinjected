"""JSON, Markdown and SARIF reports and the report command (IFJ-034)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ifinjected.homes import Platform
from ifinjected.models import Policy
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.privacy import RedactionContext
from ifinjected.reports.formats import render_json, render_markdown, render_sarif
from ifinjected.rules.catalog import builtin_rules
from tests import canaries
from tests.homes import FakeMachine
from tests.unit.test_cli import run_main


def _snapshot(tmp_path: Path) -> object:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(
        ".claude/settings.json",
        {"permissions": {"allow": ["Bash(python3 *)"], "deny": ["Read(~/.ssh/**)"]}},
    )
    return diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))


def test_json_has_a_summary_and_every_section(tmp_path: Path) -> None:
    data = json.loads(render_json(_snapshot(tmp_path)))  # type: ignore[arg-type]
    assert data["schema_version"] == 1
    assert data["tool"] == "ifinjected"
    assert data["summary"]["agents"][0]["agent"] == "claude_code"
    assert data["summary"]["strict_failure"] is True
    assert {"items", "agents", "exposures", "trifectas", "findings"} <= set(data)
    assert data["agents"][0]["channels"]
    assert all(set(f) >= {"id", "status", "severity", "summary"} for f in data["findings"])


def test_sarif_lists_every_rule_and_located_results(tmp_path: Path) -> None:
    data = json.loads(render_sarif(_snapshot(tmp_path)))  # type: ignore[arg-type]
    run = data["runs"][0]
    assert data["version"] == "2.1.0"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [r.id for r in builtin_rules()]
    bypass = [r for r in run["results"] if r["ruleId"] == "IFJ-READ-003"]
    assert bypass
    region = bypass[0]["locations"][0]["physicalLocation"].get("region")
    assert region == {"startLine": 7}
    assert all(r["level"] in {"error", "warning", "note"} for r in run["results"])
    assert len({r["partialFingerprints"]["ifinjected/v1"] for r in run["results"]}) == len(
        run["results"]
    )


def test_markdown_has_the_grade_and_a_table(tmp_path: Path) -> None:
    text = render_markdown(_snapshot(tmp_path))  # type: ignore[arg-type]
    assert "**Grade: " in text
    assert "| Agent | Grade | Verdict |" in text
    assert "`IFJ-READ-003`" in text


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeMachine:
    fake = FakeMachine(tmp_path)
    fake.workspace.mkdir(parents=True)
    fake.add_credentials()
    fake.write(".claude/settings.json", {})
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: fake.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(fake.home), canaries.USER, None)),
    )
    return fake


def test_report_writes_the_named_file_and_refuses_to_overwrite(
    machine: FakeMachine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "out.sarif"
    args = ("report", "-o", str(target), "-f", "sarif", "--workspace", str(machine.workspace))
    assert run_main(monkeypatch, *args) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert run_main(monkeypatch, *args) == 2
    assert "exists" in capsys.readouterr().err
    assert run_main(monkeypatch, *args, "--force") == 0


def test_scan_json_with_strict_still_prints_the_report(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run_main(
            monkeypatch, "scan", "--workspace", str(machine.workspace), "-f", "json", "--strict"
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["summary"]["strict_failure"] is True
