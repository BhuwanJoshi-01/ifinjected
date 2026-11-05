"""`ifinjected scan` and the bare `ifinjected` (IFJ-033)."""

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
    fake = FakeMachine(tmp_path, env={"OPENAI_API_KEY": canaries.OPENAI_KEY})
    fake.workspace.mkdir(parents=True)
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: fake.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(fake.home), canaries.USER, canaries.HOST)),
    )
    monkeypatch.chdir(fake.workspace)
    return fake


def _out(capsys: pytest.CaptureFixture[str]) -> str:
    return " ".join(capsys.readouterr().out.split())


def test_the_bare_command_scans(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    assert run_main(monkeypatch) == 0
    out = _out(capsys)
    assert "If a coding agent on this machine got prompt-injected right now" in out
    assert " F Claude Code" in out
    assert "IFJ-TRIFECTA-001" in out
    assert "Grade F" in out
    assert canaries.MARK not in out
    assert canaries.USER not in out


def test_strict_exits_1_on_a_failing_finding(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    assert run_main(monkeypatch, "scan", "--strict") == 1
    assert "IFJ-READ-001" in _out(capsys)


def test_strict_passes_when_the_policy_allows_reads(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    machine.write_workspace(
        ".ifinjected.toml", "schema_version = 1\n[policy]\nread = 'warn'\ntrifecta = 'warn'\n"
    )
    assert run_main(monkeypatch, "scan", "--strict") == 0


def test_warnings_are_folded_unless_all(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.add_credentials()
    machine.write(
        ".ssh/second", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"
    )
    machine.write(".claude/settings.json", {})
    assert run_main(monkeypatch, "scan") == 0
    folded = _out(capsys)
    assert "(+1 more)" in folded
    assert "--all lists every warning" in folded
    assert run_main(monkeypatch, "scan", "--all") == 0
    assert "(+1 more)" not in _out(capsys)


def test_no_agent_found(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "scan") == 0
    assert "No supported coding agent was found" in _out(capsys)


def test_help_still_works(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "--help") == 0
    assert "scan" in capsys.readouterr().out
