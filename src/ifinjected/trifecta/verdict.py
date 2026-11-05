"""The lethal trifecta per agent, and a grade from A to F.

Simon Willison's *lethal trifecta*: an agent that can (1) reach private data, (2) take
in content an attacker can write and (3) send data out can be made to leak the first
through the third by the second. For a coding agent:

* **private data**: the sensitive items it can reach (from the exposures);
* **untrusted input**: the repository itself (READMEs, issues pasted in, dependency
  code: always present for a coding agent), its web tools, and MCP servers that bring in
  content others write;
* **a way out**: a shell with network access, its web fetch tool (data leaves in the
  URL), and MCP servers that can write elsewhere.

Each leg is *open* through its easiest member; its gate tells whether a human stands in
the way. The grade is a pure function of the legs and the severity of what is exposed,
documented in ``docs/grading.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ifinjected.agents.base import AgentReport
from ifinjected.models import AgentId, Reach, SensitiveItem, Severity
from ifinjected.policy.exposure import Exposure
from ifinjected.policy.model import Channel, Gate, Network
from ifinjected.trifecta.classify import Capability, classify

_GATE_ORDER = (Gate.NONE, Gate.AUTOMATED, Gate.HUMAN, Gate.DENIED)


class Verdict(StrEnum):
    FULL_UNGATED = "full_ungated"
    """All three legs open, and nothing but a classifier stands in the way of any."""
    FULL_GATED = "full_gated"
    """All three legs open, but a human must approve at least one step."""
    TWO_LEGS = "two_legs"
    """One leg away: adding an MCP server or a dotfile completes it."""
    CONTAINED = "contained"


class Grade(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass(frozen=True, slots=True)
class Member:
    """One way a leg is open: what it is and the gate in front of it."""

    what: str
    gate: Gate


@dataclass(frozen=True, slots=True)
class Leg:
    members: tuple[Member, ...]

    @property
    def open(self) -> bool:
        return any(m.gate.opens for m in self.members)

    @property
    def gate(self) -> Gate:
        """The easiest gate among the open members (``denied`` when none is open)."""
        open_ = [m.gate for m in self.members if m.gate.opens]
        return min(open_, key=_GATE_ORDER.index) if open_ else Gate.DENIED

    @property
    def easiest(self) -> Member | None:
        open_ = [m for m in self.members if m.gate.opens]
        return min(open_, key=lambda m: _GATE_ORDER.index(m.gate)) if open_ else None


@dataclass(frozen=True, slots=True)
class Trifecta:
    agent: AgentId
    private: Leg
    input: Leg
    exfil: Leg
    verdict: Verdict
    grade: Grade
    worst_severity: Severity | None = None


def _reach_gate(exposure: Exposure) -> Gate:
    if exposure.reach in {Reach.NO_APPROVAL, Reach.BYPASSABLE_RULE}:
        return Gate.NONE
    if exposure.reach is Reach.AFTER_APPROVAL:
        return exposure.gate if exposure.gate is Gate.AUTOMATED else Gate.HUMAN
    return Gate.DENIED


def _private(
    exposures: list[Exposure], items: dict[tuple[str, str], SensitiveItem]
) -> tuple[Leg, Severity | None]:
    members = []
    worst: Severity | None = None
    order = list(Severity)
    for exposure in exposures:
        if not exposure.reach.reachable:
            continue
        item = items.get((exposure.item, exposure.path))
        severity = item.severity if item else Severity.MEDIUM
        if severity in {Severity.INFO, Severity.LOW}:
            continue
        members.append(Member(item.title if item else exposure.item, _reach_gate(exposure)))
        if worst is None or order.index(severity) > order.index(worst):
            worst = severity
    return Leg(tuple(members)), worst


def _input(report: AgentReport) -> Leg:
    members = [Member("the repository and its dependencies", Gate.NONE)]
    policy = report.policy
    if policy is None:
        return Leg(tuple(members))
    if policy.web_fetch is not None:
        members.append(Member("its web fetch tool", policy.web_fetch))
    if policy.web_search is not None:
        members.append(Member("its web search tool", policy.web_search))
    gates = dict(policy.mcp_gates)
    for server in report.mcp_servers:
        if server.name in gates and classify(server).has(Capability.UNTRUSTED_INPUT):
            members.append(Member(f"MCP server {server.name}", gates[server.name]))
    return Leg(tuple(members))


def _exfil(report: AgentReport) -> Leg:
    members: list[Member] = []
    policy = report.policy
    if policy is None:
        return Leg(())
    for channel in policy.channels:
        if channel.channel is not Channel.SHELL_ARBITRARY:
            continue
        gate = min(channel.gate_inside, channel.gate_outside, key=_GATE_ORDER.index)
        if channel.sandboxed:
            network = policy.sandbox.network
            if network is Network.NONE:
                gate = Gate.HUMAN if gate.opens else gate  # unlisted hosts prompt
            what = "a sandboxed shell command to an allowed host"
        else:
            what = "a shell command with full network access (curl, git push)"
        members.append(Member(what, gate))
    if policy.web_fetch is not None:
        members.append(Member("its web fetch tool (data leaves in the URL)", policy.web_fetch))
    gates = dict(policy.mcp_gates)
    for server in report.mcp_servers:
        if server.name in gates and classify(server).has(Capability.EXFILTRATION):
            members.append(Member(f"MCP server {server.name}", gates[server.name]))
    return Leg(tuple(members))


def grade_of(
    private: Leg, input_: Leg, exfil: Leg, worst: Severity | None
) -> tuple[Verdict, Grade]:
    """The verdict and grade; see docs/grading.md."""
    legs = [private.open, input_.open, exfil.open]
    if all(legs):
        gates = {private.gate, input_.gate, exfil.gate}
        if gates <= {Gate.NONE, Gate.AUTOMATED}:
            if worst is Severity.HIGH and Gate.AUTOMATED not in gates:
                return Verdict.FULL_UNGATED, Grade.F
            return Verdict.FULL_UNGATED, Grade.D
        return Verdict.FULL_GATED, Grade.C
    if sum(legs) == 2:
        return Verdict.TWO_LEGS, Grade.B
    return Verdict.CONTAINED, Grade.A


def trifecta_of(
    report: AgentReport, exposures: list[Exposure], items: dict[tuple[str, str], SensitiveItem]
) -> Trifecta:
    private, worst = _private(exposures, items)
    input_ = _input(report)
    exfil = _exfil(report)
    verdict, grade = grade_of(private, input_, exfil, worst)
    return Trifecta(report.agent, private, input_, exfil, verdict, grade, worst)


def trifectas(
    agents: tuple[AgentReport, ...],
    exposures: tuple[Exposure, ...],
    items: tuple[SensitiveItem, ...],
) -> tuple[Trifecta, ...]:
    by_key = {(i.id, i.path): i for i in items}
    return tuple(
        trifecta_of(report, [e for e in exposures if e.agent is report.agent], by_key)
        for report in agents
        if report.found
    )


_GRADE_ORDER = (Grade.A, Grade.B, Grade.C, Grade.D, Grade.F)


def machine_grade(found: tuple[Trifecta, ...]) -> Grade | None:
    """The worst grade among the agents: an attacker picks the easiest way in."""
    if not found:
        return None
    return max((t.grade for t in found), key=_GRADE_ORDER.index)
