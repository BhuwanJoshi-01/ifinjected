"""`ifinjected plan`: suggestions per agent, never applied (IFJ-035)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ifinjected.homes import Platform
from ifinjected.models import AgentId, Policy
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.plan import make_plan, render_plan_json, render_plan_text
from ifinjected.privacy import RedactionContext
from tests import canaries
from tests.gitless import tree_digest
from tests.homes import FakeMachine
from tests.unit.test_cli import run_main


def _steps(machine: FakeMachine) -> tuple:  # type: ignore[type-arg]
    machine.workspace.mkdir(parents=True, exist_ok=True)
    snapshot = diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))
    return make_plan(snapshot, str(machine.home))


def test_claude_code_gets_sandbox_denials_and_read_rules(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"allow": ["Bash(python3 *)"]}})
    steps = _steps(machine)
    claude = [s for s in steps if s.agent is AgentId.CLAUDE_CODE]
    settings = json.loads(claude[0].snippet)
    assert settings["sandbox"]["enabled"] is True
    assert "~/.ssh" in settings["sandbox"]["filesystem"]["denyRead"]
    assert "Read(~/.ssh/**)" in settings["permissions"]["deny"]
    assert "Read(~/.npmrc)" in settings["permissions"]["deny"]  # a file, not a directory
    assert any(s.snippet == "remove this allow rule" and s.file.endswith(":4") for s in claude)


def test_codex_gets_a_permissions_profile(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path, env={"OPENAI_API_KEY": canaries.OPENAI_KEY})
    machine.add_credentials()
    machine.write(".codex/config.toml", 'model = "x"\n')
    (step,) = [s for s in _steps(machine) if s.agent is AgentId.CODEX]
    assert 'default_permissions = "ifinjected"' in step.snippet
    assert '"~/.ssh" = "deny"' in step.snippet
    assert "ignore_default_excludes = false" in step.snippet


def test_opencode_is_told_to_ask(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".config/opencode/opencode.json", {})
    (step,) = [s for s in _steps(machine) if s.agent is AgentId.OPENCODE]
    assert json.loads(step.snippet) == {
        "permission": {"bash": "ask", "webfetch": "ask", "external_directory": "ask"}
    }


def test_nothing_to_do_without_reachable_credentials(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".claude/settings.json", {})
    assert render_plan_text(_steps(machine)).startswith("Nothing to change")


def test_json_plan(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    data = json.loads(render_plan_json(_steps(machine)))
    assert data[0]["agent"] == "claude_code"
    assert set(data[0]) == {"agent", "file", "snippet", "why"}


def test_the_command_changes_nothing_and_shows_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: machine.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(machine.home), canaries.USER, None)),
    )
    before = tree_digest(tmp_path)
    assert run_main(monkeypatch, "plan", "--workspace", str(machine.workspace)) == 0
    out = capsys.readouterr().out
    assert "nothing was applied" in out
    assert "~/.ssh" in out
    assert canaries.MARK not in out
    assert tree_digest(tmp_path) == before
