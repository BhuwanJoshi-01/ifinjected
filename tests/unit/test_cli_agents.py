"""`ifinjected agents` on a fake machine."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.homes import Platform
from ifinjected.privacy import RedactionContext
from tests import canaries
from tests.homes import FakeMachine
from tests.unit.test_cli import run_main


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeMachine:
    fake = FakeMachine(tmp_path)
    fake.workspace.mkdir(parents=True)
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: fake.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(fake.home), canaries.USER, canaries.HOST)),
    )
    return fake


def test_no_agent_found(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "agents", "--workspace", str(machine.workspace)) == 0
    assert "No supported coding agent was found" in capsys.readouterr().out


def test_claude_code_layers_gates_rules_and_servers(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.write(
        ".claude/settings.json",
        {"permissions": {"defaultMode": "acceptEdits", "deny": ["Read(~/.ssh/**)"]}},
    )
    machine.write(
        ".claude.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "gh-mcp"],
                    "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                }
            }
        },
    )
    assert run_main(monkeypatch, "agents", "--workspace", str(machine.workspace)) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Claude Code" in out
    assert "permission mode acceptEdits" in out
    assert "read-only commands no approval anywhere" in out
    assert "refused" in out
    assert "github" in out
    assert "env: GITHUB_TOKEN" in out
    assert canaries.MARK not in out
    assert canaries.USER not in out


def test_an_agent_can_be_asked_for_by_name(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run_main(
        monkeypatch, "agents", "--workspace", str(machine.workspace), "--agent", "claude_code"
    )
    assert code == 0
    assert "Not found on this machine" in capsys.readouterr().out
