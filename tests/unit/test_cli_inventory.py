"""`ifinjected inventory` on a fake machine."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected import cli
from ifinjected.homes import Platform
from ifinjected.privacy import RedactionContext
from tests import canaries
from tests.homes import FakeMachine
from tests.unit.test_cli import run_main


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeMachine:
    fake = FakeMachine(tmp_path)
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: fake.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(fake.home), canaries.USER, canaries.HOST)),
    )
    return fake


def test_an_empty_machine(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.workspace.mkdir(parents=True)
    assert run_main(monkeypatch, "inventory", "--workspace", str(machine.workspace)) == 0
    assert "None of the known kinds of credentials were found" in capsys.readouterr().out


def test_keys_are_listed_redacted_and_without_any_secret(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.add_credentials()
    assert run_main(monkeypatch, "inventory", "--workspace", str(machine.workspace)) == 0
    out = capsys.readouterr().out
    assert "SSH private key (no passphrase)" in out
    assert str(Path("~", ".ssh", "id_ed25519")) in " ".join(out.split())
    assert "HIGH" in out
    assert canaries.MARK not in out
    assert str(machine.home) not in out
    assert canaries.USER not in out


def test_a_bad_policy_exits_2(
    machine: FakeMachine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine.write_workspace(".ifinjected.toml", "schema_version = 9\n")
    assert run_main(monkeypatch, "inventory", "--workspace", str(machine.workspace)) == 2
    assert "not supported" in capsys.readouterr().err


def test_the_command_is_registered() -> None:
    names = {
        command.name or getattr(command.callback, "__name__", "")
        for command in cli.app.registered_commands
    }
    assert {"inventory", "policy"} <= names
