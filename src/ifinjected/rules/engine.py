"""The rule registry and evaluation.

A rule is a pure function from a :class:`~ifinjected.models.Snapshot` to findings under
its own code. Its docstring is the explanation ``ifinjected explain`` prints, and a test
keeps ``docs/rules.md`` in step with the registry. A rule that raises is a bug in this
tool: it becomes an ``unknown`` finding for that check instead of hiding every other
result, and never a pass.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, replace

from ifinjected.models import (
    FINDING_ID,
    Confidence,
    Family,
    Finding,
    Policy,
    PolicyLevel,
    Severity,
    Snapshot,
    Status,
)

RuleCheck = Callable[[Snapshot], Iterable[Finding]]

_STATUS = {
    PolicyLevel.ALLOW: Status.PASS,
    PolicyLevel.WARN: Status.WARN,
    PolicyLevel.DENY: Status.FAIL,
}
_STATUS_ORDER = (Status.PASS, Status.WARN, Status.FAIL)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    family: Family
    explanation: str
    check: RuleCheck
    sources: tuple[str, ...] = ()
    max_status: Status = Status.FAIL
    """The most a finding of this rule can be: ``warn`` for rules that report an exposure
    behind a human approval, which should never fail ``--strict`` on its own."""


class Registry:
    """Rules in registration order, which is the order they are evaluated and listed."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def rule(
        self,
        rule_id: str,
        title: str,
        *,
        sources: Iterable[str] = (),
        max_status: Status = Status.FAIL,
    ) -> Callable[[RuleCheck], RuleCheck]:
        """Register a check; its docstring becomes the explanation shown by ``explain``."""

        def register(check: RuleCheck) -> RuleCheck:
            if not FINDING_ID.fullmatch(rule_id):
                raise ValueError(f"rule id {rule_id!r} does not match IFJ-<FAMILY>-<NNN>")
            if rule_id in self._rules:
                raise ValueError(f"rule {rule_id} is registered twice")
            explanation = inspect.cleandoc(check.__doc__ or "")
            if not explanation:
                raise ValueError(f"rule {rule_id} has no docstring to explain it")
            family = Family(rule_id.split("-")[1])
            self._rules[rule_id] = Rule(
                rule_id, title, family, explanation, check, tuple(sources), max_status
            )
            return check

        return register

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules.values())

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id.upper())


def problem_status(policy: Policy | None, family: Family, cap: Status = Status.FAIL) -> Status:
    """The status of a problem in ``family`` under the policy's level, at most ``cap``."""
    status = _STATUS[(policy or Policy()).level(family)]
    if _STATUS_ORDER.index(status) > _STATUS_ORDER.index(cap):
        return cap
    return status


def _accepted(finding: Finding, policy: Policy) -> bool:
    return finding.item is not None and finding.item in policy.accept_items


def evaluate(snapshot: Snapshot, rules: Iterable[Rule]) -> tuple[Finding, ...]:
    """Run every rule in order and collect their findings.

    Findings keep their rule's code; their status follows the policy level of the rule's
    family (capped by the rule), and an item the policy accepts passes, with a note.
    """
    policy = snapshot.policy or Policy()
    findings: list[Finding] = []
    for rule in rules:
        try:
            produced = list(rule.check(snapshot))
        except Exception as exc:  # report the broken check, keep the others
            findings.append(_internal_error(rule, exc))
            continue
        for finding in produced:
            if finding.id != rule.id:
                raise ValueError(f"rule {rule.id} reported a finding as {finding.id}")
            if finding.status in {Status.WARN, Status.FAIL}:
                status = problem_status(policy, rule.family, rule.max_status)
                limitations = finding.limitations
                if _accepted(finding, policy):
                    status = Status.PASS
                    limitations = (*limitations, "Accepted in .ifinjected.toml ([accept] items).")
                finding = replace(finding, status=status, limitations=limitations)
            findings.append(finding)
    return tuple(findings)


def _internal_error(rule: Rule, exc: Exception) -> Finding:
    return Finding(
        id=rule.id,
        status=Status.UNKNOWN,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        summary=f"{rule.title}: not checked because of an internal error",
        reason=f"The check failed with {type(exc).__name__}: {exc}",
        recommended_action="Please report this as a bug, with the redacted report.",
    )
