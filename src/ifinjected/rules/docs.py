"""docs/rules.md, generated from the registry so the two can never disagree."""

from __future__ import annotations

from ifinjected.models import DEFAULT_LEVELS, Family
from ifinjected.rules.catalog import builtin_rules
from ifinjected.rules.engine import Rule

_FAMILY_TITLES = {
    Family.READ: "What agents can read",
    Family.POSTURE: "How agents are set up",
    Family.SECRET: "Credentials on this machine",
    Family.INPUT: "Untrusted input",
    Family.EXFIL: "Ways out",
    Family.MCP: "MCP servers",
    Family.HOOK: "Hooks",
    Family.TRIFECTA: "The lethal trifecta",
    Family.PROVE: "Prove mode",
    Family.DIFF: "Changes in a pull request",
    Family.CONFIG: "Configuration",
}


def explain(rule: Rule) -> str:
    """The text ``ifinjected explain CODE`` prints, and the rule's section in rules.md."""
    lines = [f"## {rule.id}: {rule.title}", "", rule.explanation, ""]
    level = DEFAULT_LEVELS[rule.family].value
    cap = " (never more than a warning)" if rule.max_status.value == "warn" else ""
    lines.append(f"Family `{rule.family.policy_key}`, default level `{level}`{cap}.")
    if rule.sources:
        lines.append("")
        lines.append("Sources: " + ", ".join(f"<{s}>" for s in rule.sources))
    return "\n".join(lines) + "\n"


def render_rules_markdown() -> str:
    out = [
        "# Rules",
        "",
        "Every finding has a stable code, `IFJ-<FAMILY>-<NNN>`; codes are never reused.",
        "Its status follows the level of its family in [`.ifinjected.toml`](policy.md):",
        "`deny` fails `--strict`, `warn` is reported, `allow` is information only.",
        "`ifinjected explain CODE` prints a section.",
        "",
        "This file is generated from the rules themselves",
        "(`uv run python -m ifinjected.rules.docs`); a test fails when the two differ.",
    ]
    by_family: dict[Family, list[Rule]] = {}
    for rule in builtin_rules():
        by_family.setdefault(rule.family, []).append(rule)
    for family in Family:
        rules = by_family.get(family)
        if not rules:
            continue
        out += ["", f"# {_FAMILY_TITLES[family]}", ""]
        for rule in rules:
            out.append(explain(rule).rstrip("\n"))
            out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


if __name__ == "__main__":
    from pathlib import Path

    Path("docs/rules.md").write_text(render_rules_markdown(), encoding="utf-8")
