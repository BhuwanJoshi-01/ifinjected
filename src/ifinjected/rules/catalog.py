"""Every built-in rule, in the order they are evaluated and listed."""

from __future__ import annotations

from ifinjected import diffing
from ifinjected.rules import flow, posture, read, secret
from ifinjected.rules.engine import Rule


def builtin_rules() -> tuple[Rule, ...]:
    rules = (
        *flow_first(),
        *read.registry,
        *posture.registry,
        *secret.registry,
        *flow_rest(),
        *diffing.registry,
    )
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("a rule id is registered in two modules")
    return tuple(rules)


def flow_first() -> tuple[Rule, ...]:
    """The trifecta verdicts lead the list: they are the summary."""
    return tuple(rule for rule in flow.registry if rule.family.value == "TRIFECTA")


def flow_rest() -> tuple[Rule, ...]:
    return tuple(rule for rule in flow.registry if rule.family.value != "TRIFECTA")


def rule_by_id(rule_id: str) -> Rule | None:
    wanted = rule_id.upper()
    return next((rule for rule in builtin_rules() if rule.id == wanted), None)
