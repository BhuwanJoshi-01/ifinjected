"""The lethal trifecta per agent and the grade (IFJ-031)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.models import AgentId, Policy, Severity
from ifinjected.orchestrator import inspect_all
from ifinjected.policy.model import Gate
from ifinjected.trifecta.verdict import (
    Grade,
    Leg,
    Member,
    Trifecta,
    Verdict,
    grade_of,
    machine_grade,
)
from tests import canaries
from tests.homes import FakeMachine


def _leg(*gates: Gate) -> Leg:
    return Leg(tuple(Member(f"m{i}", g) for i, g in enumerate(gates)))


OPEN = _leg(Gate.NONE)
CLASSIFIER = _leg(Gate.AUTOMATED)
HUMAN = _leg(Gate.HUMAN)
CLOSED = _leg(Gate.DENIED)


@pytest.mark.parametrize(
    ("private", "input_", "exfil", "worst", "expected"),
    [
        (OPEN, OPEN, OPEN, Severity.HIGH, (Verdict.FULL_UNGATED, Grade.F)),
        (OPEN, OPEN, OPEN, Severity.MEDIUM, (Verdict.FULL_UNGATED, Grade.D)),
        (CLASSIFIER, OPEN, OPEN, Severity.HIGH, (Verdict.FULL_UNGATED, Grade.D)),
        (OPEN, OPEN, HUMAN, Severity.HIGH, (Verdict.FULL_GATED, Grade.C)),
        (OPEN, OPEN, CLOSED, Severity.HIGH, (Verdict.TWO_LEGS, Grade.B)),
        (CLOSED, OPEN, OPEN, None, (Verdict.TWO_LEGS, Grade.B)),
        (CLOSED, OPEN, CLOSED, None, (Verdict.CONTAINED, Grade.A)),
    ],
)
def test_grade_of(
    private: Leg, input_: Leg, exfil: Leg, worst: Severity | None, expected: tuple[Verdict, Grade]
) -> None:
    assert grade_of(private, input_, exfil, worst) == expected


def test_a_leg_is_as_open_as_its_easiest_member() -> None:
    leg = _leg(Gate.DENIED, Gate.HUMAN, Gate.AUTOMATED)
    assert (leg.open, leg.gate) == (True, Gate.AUTOMATED)
    assert leg.easiest == Member("m2", Gate.AUTOMATED)
    assert (_leg().open, _leg(Gate.DENIED).gate) == (False, Gate.DENIED)


def _run(machine: FakeMachine) -> object:
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return inspect_all(machine.platform(), Policy(), machine.workspace)


def test_manual_mode_with_keys_on_disk_is_a_gated_trifecta(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    (trifecta,) = _run(machine).trifectas  # type: ignore[attr-defined]
    assert trifecta.private.gate is Gate.NONE  # cat ~/.ssh/id_ed25519
    assert trifecta.exfil.gate is Gate.HUMAN  # curl and WebFetch ask
    assert (trifecta.verdict, trifecta.grade) == (Verdict.FULL_GATED, Grade.C)


def test_bypass_mode_is_an_f(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    (trifecta,) = _run(machine).trifectas  # type: ignore[attr-defined]
    assert trifecta.grade is Grade.F
    assert trifecta.worst_severity is Severity.HIGH


def test_an_allowed_exfiltrating_mcp_server_completes_the_trifecta(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"allow": ["mcp__github"]}})
    machine.write(
        ".claude.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                }
            }
        },
    )
    (trifecta,) = _run(machine).trifectas  # type: ignore[attr-defined]
    assert trifecta.exfil.easiest == Member("MCP server github", Gate.NONE)
    assert any(m.what == "MCP server github" for m in trifecta.input.members)
    assert trifecta.grade is Grade.F


def test_nothing_reachable_means_two_legs_at_most(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".claude/settings.json", {})
    (trifecta,) = _run(machine).trifectas  # type: ignore[attr-defined]
    assert not trifecta.private.open
    assert trifecta.grade is Grade.B


def test_the_machine_grade_is_the_worst_agent() -> None:
    assert machine_grade(()) is None
    c = Trifecta(AgentId.CLAUDE_CODE, OPEN, OPEN, HUMAN, Verdict.FULL_GATED, Grade.C)
    f = Trifecta(AgentId.CODEX, OPEN, OPEN, OPEN, Verdict.FULL_UNGATED, Grade.F)
    assert machine_grade((c, f)) is Grade.F
    assert machine_grade((c,)) is Grade.C


def test_the_grading_document_lists_every_grade() -> None:
    text = (Path(__file__).parents[2] / "docs" / "grading.md").read_text(encoding="utf-8")
    for grade in Grade:
        assert f"| **{grade.value}** |" in text
    assert AgentId.CLAUDE_CODE  # the document is about every agent, not one
