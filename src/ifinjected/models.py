"""Typed facts and findings shared by adapters, the inventory, rules and renderers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

SCHEMA_VERSION = 1
"""Version of the snapshot/JSON report layout; bumped only for incompatible changes."""

FINDING_ID = re.compile(r"IFJ-[A-Z]+-[0-9]{3}")
"""Finding codes are part of the public contract: ``IFJ-<FAMILY>-<NNN>``, e.g. ``IFJ-READ-003``."""


class Status(StrEnum):
    """Outcome of one check.

    Only ``PASS`` means that a check ran and found nothing to report. A check that could
    not decide is ``UNKNOWN``; one that was deliberately skipped (prove mode nobody asked
    for) is ``NOT_TESTED``; one that does not apply (an agent that is not installed) is
    ``NOT_APPLICABLE``.
    """

    PASS = "pass"  # noqa: S105 - a status name, not a password
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


class Severity(StrEnum):
    """How much a finding matters, independent of how sure it is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    """How well the evidence supports a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AgentId(StrEnum):
    """The coding agents ifinjected knows how to read. The values appear in JSON and on
    the command line (``--agent codex``)."""

    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    GEMINI_CLI = "gemini_cli"
    CURSOR = "cursor"
    OPENCODE = "opencode"
    COPILOT_CLI = "copilot_cli"

    @property
    def display_name(self) -> str:
        return _AGENT_NAMES[self]


_AGENT_NAMES = {
    AgentId.CLAUDE_CODE: "Claude Code",
    AgentId.CODEX: "Codex",
    AgentId.GEMINI_CLI: "Gemini CLI",
    AgentId.CURSOR: "Cursor",
    AgentId.OPENCODE: "opencode",
    AgentId.COPILOT_CLI: "Copilot CLI",
}


class Reach(StrEnum):
    """How an agent could get at one sensitive item, worst first.

    ``NO_APPROVAL``: some way of reading it needs nobody's approval and no sandbox stops
    it. ``BYPASSABLE_RULE``: a rule of the agent denies it, but a path the rule does not
    cover (a shell, a subprocess, an MCP server) is open. ``AFTER_APPROVAL``: every open
    way asks first. ``BLOCKED_BY_RULE``: denied, with no way around the rule.
    ``BLOCKED_BY_SANDBOX``: the operating system sandbox refuses it. ``NOT_PRESENT``: the
    item does not exist here. ``UNKNOWN``: it could not be decided, for instance because a
    configuration file was unreadable or the agent's behaviour is not documented.
    """

    NO_APPROVAL = "no_approval"
    BYPASSABLE_RULE = "bypassable_rule"
    AFTER_APPROVAL = "after_approval"
    BLOCKED_BY_RULE = "blocked_by_rule"
    BLOCKED_BY_SANDBOX = "blocked_by_sandbox"
    NOT_PRESENT = "not_present"
    UNKNOWN = "unknown"

    @property
    def reachable(self) -> bool:
        """The agent can get at the item, with or without someone's approval."""
        return self in _REACHABLE

    @property
    def rank(self) -> int:
        """0 for the worst; lower ranks are reported first."""
        return _REACH_ORDER.index(self)


_REACH_ORDER = tuple(Reach)
_REACHABLE = frozenset({Reach.NO_APPROVAL, Reach.BYPASSABLE_RULE, Reach.AFTER_APPROVAL})


def worst_reach(reaches: tuple[Reach, ...] | list[Reach]) -> Reach:
    """The worst of ``reaches``; ``NOT_PRESENT`` when there are none.

    ``UNKNOWN`` ranks below every decided reach: it never hides a known exposure, and an
    item that is merely undecided does not count as reachable.
    """
    if not reaches:
        return Reach.NOT_PRESENT
    return min(reaches, key=lambda reach: reach.rank)


class Proof(StrEnum):
    """Where a reach comes from. ``CLAIMED``: worked out from configuration. ``PROVEN``:
    the probe, run under the agent's own sandbox, agreed. ``CONTRADICTED``: the probe
    found the opposite of what configuration says."""

    CLAIMED = "claimed"
    PROVEN = "proven"
    CONTRADICTED = "contradicted"


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Where a fact comes from: a file and, when known, a line and the setting's key
    (``permissions.deny[2]``, ``sandbox_workspace_write.network_access``)."""

    path: str
    line: int | None = None
    key: str | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observed fact that a finding relies on; ``value`` is ``None`` when missing.

    Values are facts about a setting or an item (``"workspace-write"``, ``"unencrypted"``),
    never the content of a credential.
    """

    source: str
    key: str
    value: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    """A diagnosis with everything a user needs to judge and verify it.

    ``agent`` is the agent the finding is about (``None`` for machine-wide findings such
    as an unencrypted SSH key) and ``item`` the sensitive item's id from the catalog.
    ``sources`` are the configuration lines it follows from. ``verify_command`` re-checks
    the result after acting on ``recommended_action``; ``caused_by`` names the finding
    this one follows from, so reports show one root cause instead of a cascade.
    """

    id: str
    status: Status
    severity: Severity
    confidence: Confidence
    summary: str
    reason: str
    agent: AgentId | None = None
    item: str | None = None
    sources: tuple[SourceRef, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    recommended_action: str | None = None
    verify_command: str | None = None
    limitations: tuple[str, ...] = ()
    caused_by: str | None = None

    def __post_init__(self) -> None:
        if not FINDING_ID.fullmatch(self.id):
            raise ValueError(f"finding id {self.id!r} does not match IFJ-<FAMILY>-<NNN>")
        if self.caused_by is not None and not FINDING_ID.fullmatch(self.caused_by):
            raise ValueError(f"caused_by {self.caused_by!r} does not match IFJ-<FAMILY>-<NNN>")
        if not self.summary.strip():
            raise ValueError(f"finding {self.id} has an empty summary")


class FailureKind(StrEnum):
    """Why a probe produced no usable facts."""

    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    NONZERO_EXIT = "nonzero_exit"
    MALFORMED_OUTPUT = "malformed_output"
    OS_ERROR = "os_error"
    PROBE_ERROR = "probe_error"
    """The probe ran, but reported that part of its own work failed."""


@dataclass(frozen=True, slots=True)
class ProbeFailure:
    """A probe that could not deliver its facts; collectors return these instead of raising."""

    probe: str
    kind: FailureKind
    detail: str


@dataclass(frozen=True, slots=True)
class RedactionCount:
    """How many values of one kind (``home_path``, ``secret_value``…) were redacted."""

    kind: str
    count: int


def utc_timestamp() -> str:
    """Current time as an ISO 8601 UTC string with second precision."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
