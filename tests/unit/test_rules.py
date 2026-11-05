"""The rule engine and the first rule families (IFJ-032)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from ifinjected.models import (
    Confidence,
    Family,
    Finding,
    Policy,
    PolicyLevel,
    Severity,
    Snapshot,
    Status,
)
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.rules.catalog import builtin_rules, rule_by_id
from ifinjected.rules.docs import render_rules_markdown
from ifinjected.rules.engine import Registry, evaluate, problem_status
from tests import canaries
from tests.homes import FakeMachine

RULES_DOC = Path(__file__).parents[2] / "docs" / "rules.md"


def test_docs_rules_md_is_generated_from_the_rules() -> None:
    assert RULES_DOC.read_text(encoding="utf-8") == render_rules_markdown(), (
        "run: uv run python -m ifinjected.rules.docs"
    )


def test_every_rule_has_a_title_an_explanation_and_a_valid_family() -> None:
    for rule in builtin_rules():
        assert rule.title
        assert rule.explanation
        assert rule.family is Family(rule.id.split("-")[1])
        assert all(s.startswith("https://") for s in rule.sources)
    assert rule_by_id("ifj-read-003") is not None
    assert rule_by_id("IFJ-NOPE-001") is None


def test_the_registry_refuses_bad_rules() -> None:
    registry = Registry()

    def documented(snapshot: Snapshot) -> Iterator[Finding]:
        """Explained."""
        yield from ()

    def undocumented(snapshot: Snapshot) -> Iterator[Finding]:
        yield from ()

    registry.rule("IFJ-READ-901", "x")(documented)
    with pytest.raises(ValueError, match="twice"):
        registry.rule("IFJ-READ-901", "x")(documented)
    with pytest.raises(ValueError, match="does not match"):
        registry.rule("WTS-READ-001", "x")(documented)
    with pytest.raises(ValueError, match="docstring"):
        registry.rule("IFJ-READ-902", "x")(undocumented)


def test_a_rule_that_raises_becomes_unknown_never_a_pass() -> None:
    registry = Registry()

    @registry.rule("IFJ-READ-903", "Broken")
    def broken(snapshot: Snapshot) -> Iterator[Finding]:
        """Always fails."""
        raise RuntimeError("boom")

    (finding,) = evaluate(Snapshot("0", "t", "linux"), registry)
    assert (finding.id, finding.status) == ("IFJ-READ-903", Status.UNKNOWN)


def test_status_follows_the_family_level_capped_by_the_rule() -> None:
    policy = Policy(levels=((Family.SECRET, PolicyLevel.DENY),))
    assert problem_status(policy, Family.SECRET) is Status.FAIL
    assert problem_status(policy, Family.SECRET, cap=Status.WARN) is Status.WARN
    assert problem_status(Policy(), Family.SECRET) is Status.WARN
    allow = Policy(levels=((Family.READ, PolicyLevel.ALLOW),))
    assert problem_status(allow, Family.READ) is Status.PASS


def _diagnosed(machine: FakeMachine, policy: Policy | None = None) -> Snapshot:
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return diagnose(inspect_all(machine.platform(), policy or Policy(), machine.workspace))


def _ids(snapshot: Snapshot) -> dict[str, list[Finding]]:
    found: dict[str, list[Finding]] = {}
    for finding in snapshot.findings:
        found.setdefault(finding.id, []).append(finding)
    return found


def test_a_developer_machine_in_manual_mode(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path, env={"OPENAI_API_KEY": canaries.OPENAI_KEY})
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    snapshot = _diagnosed(machine)
    found = _ids(snapshot)
    read = {f.item for f in found["IFJ-READ-001"]}
    assert {"ssh.key", "env.variables"} <= read  # cat and echo need no approval
    assert all(f.status is Status.FAIL for f in found["IFJ-READ-001"])
    assert found["IFJ-POSTURE-003"][0].status is Status.WARN  # no sandbox
    assert [f.item for f in found["IFJ-SECRET-001"]] == ["ssh.key"]
    assert "IFJ-POSTURE-001" not in found
    assert canaries.MARK not in repr(snapshot.findings)


def test_a_walked_around_deny_rule_points_at_its_line(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(
        ".claude/settings.json",
        {"permissions": {"allow": ["Bash(python3 *)"], "deny": ["Read(~/.ssh/**)"]}},
    )
    (finding,) = [
        f for f in _diagnosed(machine).findings if f.id == "IFJ-READ-003" and f.item == "ssh.key"
    ]
    assert finding.status is Status.FAIL
    assert finding.sources[0].line == 7
    assert "walked around" in finding.summary


def test_bypass_mode_and_a_sandbox_that_cannot_run(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(
        ".claude/settings.json",
        {"permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": True}},
    )
    found = _ids(_diagnosed(machine))
    # Posture warns by default; what bypass mode exposes fails under read and trifecta.
    assert found["IFJ-POSTURE-001"][0].status is Status.WARN
    assert found["IFJ-POSTURE-001"][0].severity is Severity.HIGH
    assert found["IFJ-POSTURE-004"][0].severity is Severity.HIGH


def test_the_sandbox_reading_keys_is_its_own_finding(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write_at(machine.root / "usr" / "bin" / "bwrap", b"x")
    machine.write(".claude/settings.json", {"sandbox": {"enabled": True}})
    found = _ids(_diagnosed(machine))
    assert "ssh.key" in {f.item for f in found["IFJ-READ-004"]}
    assert "IFJ-POSTURE-003" not in found


def test_accepted_items_pass_with_a_note(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".claude/settings.json", {})
    snapshot = _diagnosed(machine, Policy(accept_items=("ssh.key",)))
    ssh = [f for f in snapshot.findings if f.item == "ssh.key"]
    assert ssh
    assert all(f.status is Status.PASS for f in ssh)
    assert all("Accepted" in " ".join(f.limitations) for f in ssh)


def test_an_unreadable_settings_file_is_a_config_finding(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".claude/settings.json", "{oops")
    found = _ids(_diagnosed(machine))
    assert found["IFJ-CONFIG-001"][0].confidence is Confidence.HIGH


def test_every_finding_code_is_a_registered_rule(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path, env={"GITHUB_TOKEN": canaries.GH_TOKEN})
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"defaultMode": "auto"}})
    registered = {rule.id for rule in builtin_rules()}
    for finding in _diagnosed(machine).findings:
        assert finding.id in registered
        assert re.fullmatch(r"IFJ-[A-Z]+-\d{3}", finding.id)
