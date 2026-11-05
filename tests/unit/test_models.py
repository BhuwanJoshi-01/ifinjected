import dataclasses
import re

import pytest

from ifinjected.models import (
    SCHEMA_VERSION,
    AgentId,
    Confidence,
    Evidence,
    FailureKind,
    Finding,
    ProbeFailure,
    Proof,
    Reach,
    Severity,
    SourceRef,
    Status,
    utc_timestamp,
    worst_reach,
)


def test_status_values_are_the_documented_json_strings() -> None:
    assert [s.value for s in Status] == [
        "pass",
        "warn",
        "fail",
        "unknown",
        "not_applicable",
        "not_tested",
    ]


def test_enums_compare_equal_to_their_json_strings() -> None:
    assert Status.UNKNOWN == "unknown"
    assert Severity.HIGH == "high"
    assert Confidence.MEDIUM == "medium"
    assert AgentId.CLAUDE_CODE == "claude_code"
    assert Reach.BYPASSABLE_RULE == "bypassable_rule"
    assert Proof.CONTRADICTED == "contradicted"


def test_agent_ids_are_the_documented_strings_with_display_names() -> None:
    assert [(a.value, a.display_name) for a in AgentId] == [
        ("claude_code", "Claude Code"),
        ("codex", "Codex"),
        ("gemini_cli", "Gemini CLI"),
        ("cursor", "Cursor"),
        ("opencode", "opencode"),
        ("copilot_cli", "Copilot CLI"),
    ]


def test_reach_runs_from_worst_to_undecided() -> None:
    assert [r.value for r in Reach] == [
        "no_approval",
        "bypassable_rule",
        "after_approval",
        "blocked_by_rule",
        "blocked_by_sandbox",
        "not_present",
        "unknown",
    ]
    assert [r.rank for r in Reach] == list(range(len(Reach)))


def test_only_the_first_three_reaches_are_reachable() -> None:
    assert {r for r in Reach if r.reachable} == {
        Reach.NO_APPROVAL,
        Reach.BYPASSABLE_RULE,
        Reach.AFTER_APPROVAL,
    }


@pytest.mark.parametrize(
    ("reaches", "worst"),
    [
        ([], Reach.NOT_PRESENT),
        ([Reach.BLOCKED_BY_SANDBOX, Reach.AFTER_APPROVAL], Reach.AFTER_APPROVAL),
        ([Reach.AFTER_APPROVAL, Reach.BYPASSABLE_RULE], Reach.BYPASSABLE_RULE),
        ([Reach.UNKNOWN, Reach.BLOCKED_BY_RULE], Reach.BLOCKED_BY_RULE),
        ([Reach.UNKNOWN], Reach.UNKNOWN),
        ((Reach.NO_APPROVAL, Reach.UNKNOWN), Reach.NO_APPROVAL),
    ],
)
def test_worst_reach_never_lets_unknown_hide_a_known_exposure(
    reaches: list[Reach], worst: Reach
) -> None:
    assert worst_reach(reaches) is worst


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "id": "IFJ-READ-003",
        "status": Status.FAIL,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "summary": "A deny rule for ~/.aws can be bypassed through Bash.",
        "reason": "Read(~/.aws/**) is denied, but Bash runs without a sandbox.",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def test_finding_defaults_to_no_agent_no_item_and_no_evidence() -> None:
    finding = _finding()
    assert (finding.agent, finding.item) == (None, None)
    assert finding.sources == ()
    assert finding.evidence == ()


def test_finding_carries_agent_item_and_configuration_lines() -> None:
    finding = _finding(
        agent=AgentId.CLAUDE_CODE,
        item="aws.credentials",
        sources=(SourceRef("~/.claude/settings.json", 12, "permissions.deny[0]"),),
    )
    assert finding.sources[0] == SourceRef("~/.claude/settings.json", 12, "permissions.deny[0]")
    assert finding.agent is AgentId.CLAUDE_CODE


@pytest.mark.parametrize(
    "bad_id", ["IFJ-READ-1", "ifj-read-001", "WTS-PORT-001", "IFJ-READ-0011", "IFJ-READ-00A", ""]
)
def test_finding_rejects_malformed_ids(bad_id: str) -> None:
    with pytest.raises(ValueError, match="does not match"):
        _finding(id=bad_id)


def test_finding_rejects_malformed_causes_and_empty_summaries() -> None:
    with pytest.raises(ValueError, match="caused_by"):
        _finding(caused_by="READ-001")
    with pytest.raises(ValueError, match="empty summary"):
        _finding(summary="  ")


def test_findings_and_evidence_are_immutable() -> None:
    finding = _finding(evidence=(Evidence("claude_code", "sandbox.enabled", "false"),))
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = Status.PASS  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.evidence[0].value = "true"  # type: ignore[misc]


def test_failure_kinds_are_the_documented_json_strings() -> None:
    assert [k.value for k in FailureKind] == [
        "not_found",
        "permission_denied",
        "timeout",
        "nonzero_exit",
        "malformed_output",
        "os_error",
        "probe_error",
    ]


def test_probe_failure_keeps_probe_kind_and_detail() -> None:
    failure = ProbeFailure("codex sandbox", FailureKind.TIMEOUT, "no answer within 10 s")
    assert (failure.probe, failure.kind, failure.detail) == (
        "codex sandbox",
        FailureKind.TIMEOUT,
        "no answer within 10 s",
    )


def test_schema_version_starts_at_one() -> None:
    assert SCHEMA_VERSION == 1


def test_utc_timestamp_is_iso_8601_utc() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", utc_timestamp())
