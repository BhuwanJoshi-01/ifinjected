"""Every built-in rule, in the order they are evaluated and listed."""

from __future__ import annotations

from ifinjected.rules import posture, read, secret
from ifinjected.rules.engine import Rule


def builtin_rules() -> tuple[Rule, ...]:
    rules = (*read.registry, *posture.registry, *secret.registry)
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("a rule id is registered in two modules")
    return tuple(rules)


def rule_by_id(rule_id: str) -> Rule | None:
    wanted = rule_id.upper()
    return next((rule for rule in builtin_rules() if rule.id == wanted), None)
