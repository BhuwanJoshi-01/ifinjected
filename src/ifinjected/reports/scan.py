"""The scan report: one grade per agent, then what to fix, most urgent first.

Built from an already redacted snapshot. Failures are shown in full; warnings of the
same rule are folded into one line with a count unless ``--all`` asks for every one.
"""

from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.text import Text

from ifinjected.models import Finding, Severity, Snapshot, Status
from ifinjected.policy.model import Gate
from ifinjected.reports.terminal import display_path, redaction_line
from ifinjected.trifecta.verdict import Trifecta, machine_grade

_GRADE_STYLE = {"A": "bold white on green", "B": "bold black on green", "C": "bold black on yellow",
                "D": "bold white on red", "F": "bold white on red"}  # fmt: skip
_VERDICT = {
    "full_ungated": "lethal trifecta: nothing but {who} stands in the way",
    "full_gated": "lethal trifecta behind your approval",
    "two_legs": "two of three legs: one change away from a trifecta",
    "contained": "contained",
}
_GATE = {Gate.NONE: "no approval", Gate.AUTOMATED: "a classifier", Gate.HUMAN: "your approval",
         Gate.DENIED: "closed"}  # fmt: skip
_STATUS_STYLE = {Status.FAIL: "bold red", Status.WARN: "yellow", Status.UNKNOWN: "magenta"}
_SEVERITY_ORDER = list(Severity)[::-1]


def _headline(trifecta: Trifecta) -> str:
    text = _VERDICT[trifecta.verdict.value]
    gates = {trifecta.private.gate, trifecta.input.gate, trifecta.exfil.gate}
    who = "a classifier" if Gate.AUTOMATED in gates else "luck"
    return text.format(who=who)


def _trifecta(trifecta: Trifecta, console: Console) -> None:
    line = Text()
    line.append(f" {trifecta.grade.value} ", style=_GRADE_STYLE[trifecta.grade.value])
    line.append(f"  {trifecta.agent.display_name}", style="bold")
    line.append(f"  {_headline(trifecta)}")
    console.print(line)
    for name, leg in (
        ("private data", trifecta.private),
        ("untrusted input", trifecta.input),
        ("a way out", trifecta.exfil),
    ):
        member = leg.easiest
        row = Text(f"     {name:<16}")
        if member is None:
            row.append("closed", style="green")
        else:
            style = "bold red" if member.gate is Gate.NONE else "yellow"
            row.append(_GATE[member.gate], style=style)
            row.append(f" · {member.what}", style="dim")
            more = sum(1 for m in leg.members if m.gate.opens) - 1
            if more > 0:
                row.append(f" (+{more})", style="dim")
        console.print(row)


def _sort_key(finding: Finding) -> tuple[int, int, str]:
    status = 0 if finding.status is Status.FAIL else 1 if finding.status is Status.UNKNOWN else 2
    return status, _SEVERITY_ORDER.index(finding.severity), finding.id


def _finding(finding: Finding, console: Console) -> None:
    line = Text()
    line.append(f"{finding.status.value.upper():<5} ", style=_STATUS_STYLE.get(finding.status, ""))
    line.append(f"{finding.id:<17}", style="bold")
    line.append(finding.summary)
    console.print(line)
    console.print(Text(f"      {finding.reason}", style="dim"))
    for source in finding.sources[:1]:
        if source.line is not None:
            console.print(Text(f"      at {display_path(source.path)}:{source.line}", style="dim"))
    if finding.recommended_action:
        fix = Text("      fix: ", style="green")
        fix.append(finding.recommended_action)
        console.print(fix)


def render_scan(snapshot: Snapshot, console: Console, *, show_all: bool = False) -> None:
    grade = machine_grade(snapshot.trifectas)
    header = Text("ifinjected", style="bold")
    header.append(f" {snapshot.tool_version} · {snapshot.system}", style="dim")
    if snapshot.workspace:
        header.append(f" · workspace {display_path(snapshot.workspace)}", style="dim")
    console.print(header)
    console.print(
        Text("If a coding agent on this machine got prompt-injected right now:", style="dim")
    )
    console.print()
    if not snapshot.trifectas:
        console.print(Text("No supported coding agent was found on this machine."))
    for trifecta in snapshot.trifectas:
        _trifecta(trifecta, console)
        console.print()
    problems = [
        f for f in snapshot.findings if f.status in {Status.FAIL, Status.WARN, Status.UNKNOWN}
    ]
    problems.sort(key=_sort_key)
    shown = [f for f in problems if f.status is not Status.WARN or show_all]
    folded: dict[str, list[Finding]] = defaultdict(list)
    if not show_all:
        for finding in problems:
            if finding.status is Status.WARN:
                folded[finding.id].append(finding)
    for finding in shown:
        _finding(finding, console)
    if folded:
        if shown:
            console.print()
        for rule_id, group in sorted(folded.items(), key=lambda kv: _sort_key(kv[1][0])):
            line = Text()
            line.append("WARN  ", style="yellow")
            line.append(f"{rule_id:<17}", style="bold")
            first = group[0].summary
            line.append(first if len(group) == 1 else f"{first} (+{len(group) - 1} more)")
            console.print(line)
    failed = sum(1 for f in problems if f.status is Status.FAIL)
    passed = sum(1 for f in snapshot.findings if f.status is Status.PASS)
    console.print()
    summary = Text()
    if grade is not None:
        summary.append("Grade ", style="bold")
        summary.append(f" {grade.value} ", style=_GRADE_STYLE[grade.value])
        summary.append("  ")
    summary.append(f"{len(problems)} problem(s), {failed} failing --strict")
    if passed:
        summary.append(f", {passed} accepted")
    summary.append(f" · {len(snapshot.items)} sensitive item(s) on this machine")
    console.print(summary)
    hints = (
        "ifinjected explain CODE explains a finding; ifinjected agents shows each agent's setup."
    )
    if not show_all and folded:
        hints = "--all lists every warning. " + hints
    console.print(Text(hints, style="dim"))
    redacted = redaction_line(snapshot)
    if redacted:
        console.print(Text(redacted, style="dim"))
