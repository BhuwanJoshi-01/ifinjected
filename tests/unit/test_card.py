"""Share card, share text and badge: a grade and counts, nothing that identifies you (IFJ-036)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from ifinjected.homes import Platform
from ifinjected.models import Policy
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.privacy import RedactionContext
from ifinjected.reports.card import render_badge, render_card, render_share_text
from tests import canaries
from tests.contract.test_canary_secrets import _messy
from tests.unit.test_cli import run_main


def _snapshot(tmp_path: Path) -> object:
    machine = _messy(tmp_path)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))


@pytest.mark.parametrize("detail", [False, True])
def test_the_card_holds_no_path_name_or_secret(tmp_path: Path, detail: bool) -> None:
    snapshot = _snapshot(tmp_path)
    svg = render_card(snapshot, detail=detail)  # type: ignore[arg-type]
    ET.fromstring(svg)  # noqa: S314 - our own output, checked for being well-formed
    for forbidden in (
        canaries.MARK,
        canaries.USER,
        canaries.HOST,
        ".ssh",
        ".aws",
        "gh",
        "remote",
        "/",
    ):
        if forbidden == "/":
            body = svg.replace("http://www.w3.org/2000/svg", "").replace(
                "github.com/BhuwanJoshi-01/ifinjected", ""
            )
            assert "/home" not in body
            continue
        if forbidden == "gh":
            assert ">gh<" not in svg  # an MCP server name
            continue
        assert forbidden not in svg
    assert "Claude Code" in svg
    assert ("reachable:" in svg) is detail


def test_share_text_and_badge(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    text = render_share_text(snapshot)  # type: ignore[arg-type]
    assert text.startswith("If one of my coding agents got prompt-injected")
    assert "uvx ifinjected" in text
    assert canaries.USER not in text
    badge = render_badge(snapshot)  # type: ignore[arg-type]
    ET.fromstring(badge)  # noqa: S314 - our own output
    assert 'aria-label="ifinjected: grade ' in badge


def test_without_agents_the_card_says_so(tmp_path: Path) -> None:
    from tests.homes import FakeMachine

    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    snapshot = diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))
    assert "No coding agent found" in render_card(snapshot)
    assert "no agent" in render_badge(snapshot)
    assert "found no coding agent" in render_share_text(snapshot)


def test_the_commands_write_only_the_named_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine = _messy(tmp_path / "m")
    machine.workspace.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: machine.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(machine.home), canaries.USER, canaries.HOST)),
    )
    out = tmp_path / "card.svg"
    assert run_main(monkeypatch, "card", "-o", str(out), "--workspace", str(machine.workspace)) == 0
    assert out.read_text(encoding="utf-8").startswith("<svg")
    assert run_main(monkeypatch, "card", "-o", str(out), "--workspace", str(machine.workspace)) == 2
    assert run_main(monkeypatch, "share", "--workspace", str(machine.workspace)) == 0
    assert run_main(monkeypatch, "badge", "--workspace", str(machine.workspace)) == 0
    printed = capsys.readouterr().out
    assert canaries.MARK not in printed
    assert "<svg" in printed
