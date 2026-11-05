"""`ifinjected explain` and `ifinjected rules`."""

from __future__ import annotations

import pytest

from ifinjected.rules.catalog import builtin_rules
from tests.unit.test_cli import run_main


def test_explain_prints_the_rules_section(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "explain", "ifj-read-003") == 0
    out = capsys.readouterr().out
    assert out.startswith("## IFJ-READ-003: A deny rule can be walked around")
    assert "Sources: <https://code.claude.com/docs/en/permissions>" in out


def test_an_unknown_code_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "explain", "IFJ-NOPE-001") == 2
    assert "unknown finding code" in capsys.readouterr().err


def test_rules_lists_every_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "rules") == 0
    out = capsys.readouterr().out
    assert all(rule.id in out for rule in builtin_rules())
