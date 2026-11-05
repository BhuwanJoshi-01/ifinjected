"""POSTURE and CONFIG: how each agent is set up, and what could not be read."""

from __future__ import annotations

from collections.abc import Iterator

from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import Confidence, Evidence, Finding, Severity, Snapshot, SourceRef, Status
from ifinjected.policy.model import Channel
from ifinjected.policy.patterns import inside
from ifinjected.rules.engine import Registry
from ifinjected.rules.shared import agents_found

registry = Registry()

CLAUDE_DOCS = "https://code.claude.com/docs/en/permissions"
SANDBOX_DOCS = "https://code.claude.com/docs/en/sandboxing"


def _mode_source(report: object) -> tuple[SourceRef, ...]:
    for name, _value, source in getattr(report, "settings", ()):
        if name == "permission mode" and source is not None:
            return (source,)
    return ()


@registry.rule("IFJ-POSTURE-001", "Approvals are turned off", sources=(CLAUDE_DOCS,))
def approvals_off(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent runs in a mode that skips permission prompts (Claude Code's
    ``bypassPermissions``). Every tool call, shell command and MCP call runs without
    anyone looking; an injected instruction acts at once. Use this mode only in a
    disposable container or VM, never on a machine with your credentials."""
    for report in agents_found(snapshot):
        if report.mode == "bypassPermissions":
            yield Finding(
                "IFJ-POSTURE-001",
                Status.FAIL,
                Severity.HIGH,
                Confidence.HIGH,
                f"{report.agent.display_name} runs every action without asking (bypassPermissions)",
                "Permission prompts are skipped, so nothing stands between an injected "
                "instruction and its effect.",
                agent=report.agent,
                sources=_mode_source(report),
                recommended_action="Set permissions.defaultMode to default or acceptEdits, and "
                'permissions.disableBypassPermissionsMode to "disable" in managed settings.',
                verify_command="ifinjected agents",
            )


@registry.rule(
    "IFJ-POSTURE-002", "A classifier approves actions instead of you", sources=(CLAUDE_DOCS,)
)
def classifier_mode(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent runs in a mode where a model decides whether an action may run (Claude
    Code's ``auto`` mode). That stops many mistakes, but an approval made by a model can
    be argued with: prompt injection is an attack on exactly that kind of judgement."""
    for report in agents_found(snapshot):
        if report.mode == "auto":
            yield Finding(
                "IFJ-POSTURE-002",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name} lets a classifier approve shell commands and reads",
                "In auto mode a background classifier, not you, decides whether actions run.",
                agent=report.agent,
                sources=_mode_source(report),
                recommended_action="Keep credentials out of reach of the agent (sandbox with "
                "denyRead, deny rules) so that a talked-around classifier has nothing to leak.",
                verify_command="ifinjected agents",
            )


@registry.rule(
    "IFJ-POSTURE-003", "Shell commands run without an OS sandbox", sources=(SANDBOX_DOCS,)
)
def no_sandbox(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent's shell commands run with your full rights: no operating-system sandbox
    limits what they read, write or connect to. Deny rules then only cover the commands
    the agent recognises; a script it writes and runs is not covered."""
    for report in agents_found(snapshot):
        policy = report.policy
        if policy is None:
            continue
        has_shell = any(c.channel is Channel.SHELL_ARBITRARY for c in policy.channels)
        if has_shell and not policy.sandbox.enabled:
            yield Finding(
                "IFJ-POSTURE-003",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name} runs shell commands without a sandbox",
                "Commands can read, write and connect anywhere you can.",
                agent=report.agent,
                recommended_action="Turn the sandbox on (Claude Code: sandbox.enabled), and "
                "deny reads of credential directories in sandbox.filesystem.denyRead.",
                verify_command="ifinjected agents",
            )


@registry.rule("IFJ-POSTURE-004", "The sandbox is on but cannot run here", sources=(SANDBOX_DOCS,))
def sandbox_unavailable(snapshot: Snapshot) -> Iterator[Finding]:
    """The configuration enables the sandbox, but it cannot run on this system (no
    bubblewrap on Linux, native Windows). Claude Code then runs commands unsandboxed
    unless ``sandbox.failIfUnavailable`` is set: the protection you configured is not
    there."""
    for report in agents_found(snapshot):
        sandbox = report.policy.sandbox if report.policy else None
        if sandbox is not None and sandbox.enabled and sandbox.available is False:
            yield Finding(
                "IFJ-POSTURE-004",
                Status.FAIL,
                Severity.HIGH,
                Confidence.HIGH,
                f"{report.agent.display_name}'s sandbox is enabled but cannot run on this system",
                "Commands run unsandboxed although the configuration asks for a sandbox.",
                agent=report.agent,
                sources=(sandbox.source,) if sandbox.source else (),
                recommended_action="Install bubblewrap (and socat) on Linux, use WSL2 on Windows, "
                "and set sandbox.failIfUnavailable to true so it never silently runs without.",
                verify_command="ifinjected agents",
            )


@registry.rule("IFJ-POSTURE-005", "The sandbox has an escape hatch", sources=(SANDBOX_DOCS,))
def sandbox_escape(snapshot: Snapshot) -> Iterator[Finding]:
    """Settings let commands run outside the sandbox: commands listed in
    ``excludedCommands`` always do, and with ``allowUnsandboxedCommands`` (the default) a
    command that fails in the sandbox can be retried outside it after a prompt."""
    for report in agents_found(snapshot):
        sandbox = report.policy.sandbox if report.policy else None
        if sandbox is None or not sandbox.effective or not sandbox.escape_hatches:
            continue
        yield Finding(
            "IFJ-POSTURE-005",
            Status.WARN,
            Severity.LOW,
            Confidence.HIGH,
            f"{report.agent.display_name}'s sandbox can be left: "
            + "; ".join(sandbox.escape_hatches),
            "Commands that run outside the sandbox have your full access.",
            agent=report.agent,
            evidence=tuple(Evidence("sandbox", "escape", e) for e in sandbox.escape_hatches),
            recommended_action="Set sandbox.allowUnsandboxedCommands to false and keep "
            "excludedCommands to the few tools that cannot work sandboxed.",
            verify_command="ifinjected agents",
        )


@registry.rule(
    "IFJ-POSTURE-006", "Extra working directories open credential locations", sources=(CLAUDE_DOCS,)
)
def wide_directories(snapshot: Snapshot) -> Iterator[Finding]:
    """A directory added to the agent's working directories (``additionalDirectories``)
    contains credentials, or is your whole home. Files there become readable without a
    prompt."""
    for report in agents_found(snapshot):
        policy = report.policy
        if policy is None:
            continue
        extra = policy.working_dirs[1:] if snapshot.workspace else policy.working_dirs
        files = [i for i in snapshot.items if i.path != ENVIRONMENT]
        for directory in extra:
            exposed = [i for i in files if inside(directory, i.path)]
            if exposed:
                yield Finding(
                    "IFJ-POSTURE-006",
                    Status.FAIL,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"{report.agent.display_name} treats {directory} as a working directory, "
                    f"which holds {len(exposed)} sensitive item(s)",
                    "Files in working directories are read without a prompt.",
                    agent=report.agent,
                    evidence=tuple(Evidence("inventory", "item", i.path) for i in exposed[:10]),
                    recommended_action="Remove the directory from additionalDirectories, or add "
                    "a narrower one that holds no credentials.",
                    verify_command="ifinjected agents",
                )


@registry.rule("IFJ-CONFIG-001", "Agent configuration could not be read")
def unreadable(snapshot: Snapshot) -> Iterator[Finding]:
    """A configuration file of an agent exists but could not be read or understood (not
    valid JSON or TOML, too large, permission denied). What the agent may do is then
    uncertain: results that depend on it are marked uncertain, never safe."""
    for report in agents_found(snapshot):
        for layer in report.layers:
            if layer.skipped:
                yield Finding(
                    "IFJ-CONFIG-001",
                    Status.WARN,
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    f"{report.agent.display_name} configuration could not be read: {layer.path}",
                    f"The file {layer.skipped}.",
                    agent=report.agent,
                    sources=(SourceRef(layer.path),),
                    recommended_action="Fix the file; the agent itself may be ignoring it too.",
                    verify_command="ifinjected agents",
                )
