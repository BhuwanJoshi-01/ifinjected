"""`ifinjected policy`: the effective policy and where each value comes from."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.test_cli import run_main


def test_defaults_when_the_workspace_has_no_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert run_main(monkeypatch, "policy", "--workspace", str(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "Built-in defaults" in out
    assert "policy.read" in out
    assert "deny" in out


def test_values_from_the_file_show_their_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / ".ifinjected.toml").write_text(
        "schema_version = 1\n[policy]\nsecret = 'deny'\n", encoding="utf-8"
    )
    assert run_main(monkeypatch, "policy", "--workspace", str(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "Policy from" in out
    line = next(line for line in out.splitlines() if "policy.secret" in line)
    assert "deny" in line
    assert "default: warn" in line


def test_an_unusable_file_exits_2_naming_the_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / ".ifinjected.toml").write_text(
        "schema_version = 1\n[scan]\nyolo = true\n", encoding="utf-8"
    )
    assert run_main(monkeypatch, "policy", "--workspace", str(tmp_path)) == 2
    assert "unknown key scan.yolo" in capsys.readouterr().err
