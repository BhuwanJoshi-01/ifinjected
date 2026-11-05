"""What an agent may do, reduced to one shape for every agent.

An adapter reads an agent's configuration layers and produces an
:class:`EffectivePolicy`: the *channels* through which the agent can read a file (its
file tools, the shell, MCP servers…), the *gate* in front of each (nobody, a human, an
automated classifier, or a refusal), the agent's own rules, and the operating-system
sandbox, if any. The reach engine then decides, item by item, what an injected agent
could get at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ifinjected.models import AgentId, SourceRef


class Channel(StrEnum):
    """A way for an agent to get at a file's content.

    ``file_tool``: the agent's own read tool. ``shell_recognized``: shell commands the
    agent parses and applies its file rules to (Claude Code's ``cat``, ``head``…).
    ``shell_arbitrary``: anything else the shell can run: a Python one-liner, a script,
    ``grep -r``; no file rule sees what it opens. ``mcp``: a local MCP server running with
    the user's rights. ``hook``: commands the agent runs on events.
    """

    FILE_TOOL = "file_tool"
    SHELL_RECOGNIZED = "shell_recognized"
    SHELL_ARBITRARY = "shell_arbitrary"
    MCP = "mcp"
    HOOK = "hook"


class Gate(StrEnum):
    """What stands between an injected agent and an action.

    ``none``: it just happens. ``automated``: a classifier or reviewer model decides,
    which an injection may talk its way past. ``human``: someone is asked. ``denied``: a
    rule of the agent refuses it.
    """

    NONE = "none"
    AUTOMATED = "automated"
    HUMAN = "human"
    DENIED = "denied"

    @property
    def opens(self) -> bool:
        return self is not Gate.DENIED


class Precedence(StrEnum):
    """How an agent picks between rules that match the same path.

    ``deny_first``: deny beats ask beats allow, wherever each is written (Claude Code,
    Cursor). ``last_match``: the last matching rule wins (opencode).
    """

    DENY_FIRST = "deny_first"
    LAST_MATCH = "last_match"


@dataclass(frozen=True, slots=True)
class ReadRule:
    """A rule about reading paths: an absolute pattern, its decision, the channels the
    agent applies it to, and where it was written."""

    pattern: str
    decision: Gate
    channels: frozenset[Channel]
    source: SourceRef | None = None


@dataclass(frozen=True, slots=True)
class ChannelPolicy:
    """One channel of one agent.

    ``gate_inside`` applies to paths in the working directories, ``gate_outside`` to
    everything else, when no rule matches. ``sandboxed``: the OS sandbox applies to what
    this channel runs (Claude Code's Bash, but not its file tools or MCP servers).
    ``note`` explains a channel in a report ("MCP server filesystem").
    """

    channel: Channel
    gate_inside: Gate
    gate_outside: Gate
    sandboxed: bool = False
    note: str | None = None
    source: SourceRef | None = None


class Network(StrEnum):
    NONE = "none"
    ALLOWLIST = "allowlist"
    OPEN = "open"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """The operating-system sandbox commands run in.

    ``enabled`` is what the configuration says; ``available`` whether it can work on
    this system (``None`` when unknown). Reads are allowed everywhere except
    ``read_deny`` unless ``read_only`` lists the only readable places. ``escape_hatches``
    are settings that let a command run outside the sandbox (Claude Code's
    ``allowUnsandboxedCommands``).
    """

    enabled: bool = False
    available: bool | None = None
    read_deny: tuple[str, ...] = ()
    read_only: tuple[str, ...] | None = None
    network: Network = Network.UNKNOWN
    allowed_domains: tuple[str, ...] = ()
    escape_hatches: tuple[str, ...] = ()
    source: SourceRef | None = None
    unlisted_hosts: Gate = Gate.HUMAN
    """What happens when a sandboxed command connects to a host the sandbox does not
    allow: Claude Code's proxy asks (in Manual mode), Codex's sandbox refuses."""

    @property
    def effective(self) -> bool:
        return self.enabled and self.available is not False


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """Everything the reach engine needs about one agent in one workspace.

    ``unknowns`` lists what could not be decided (an unreadable layer, an undocumented
    setting); reaches that depend on them are reported as uncertain.
    """

    agent: AgentId
    working_dirs: tuple[str, ...] = ()
    channels: tuple[ChannelPolicy, ...] = ()
    rules: tuple[ReadRule, ...] = ()
    precedence: Precedence = Precedence.DENY_FIRST
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)
    unknowns: tuple[str, ...] = ()
    web_fetch: Gate | None = None
    """The gate of the agent's own web fetch tool; ``None`` when it has none."""
    web_search: Gate | None = None
    mcp_gates: tuple[tuple[str, Gate], ...] = ()
    """Every enabled MCP server by name, with the gate in front of its tools."""
    inherits_secret_env: bool | None = True
    """Whether commands inherit variables with secret-looking names (Codex can strip them)."""
