"""READ: what each agent can read, and around which rules."""

from __future__ import annotations

from collections.abc import Iterator

from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import (
    Confidence,
    Evidence,
    Finding,
    Reach,
    Severity,
    Snapshot,
    Status,
)
from ifinjected.rules.engine import Registry
from ifinjected.rules.shared import (
    agents_found,
    exposures_of,
    how,
    item_evidence,
    item_of,
    item_source,
)

registry = Registry()

CLAUDE_DOCS = "https://code.claude.com/docs/en/permissions"
SANDBOX_DOCS = "https://code.claude.com/docs/en/sandboxing"
_SERIOUS = {Severity.HIGH, Severity.MEDIUM}
_TRANSCRIPTS = "agent.transcripts"


@registry.rule("IFJ-READ-001", "A credential is readable without approval", sources=(CLAUDE_DOCS,))
def without_approval(snapshot: Snapshot) -> Iterator[Finding]:
    """An injected agent can read this credential without anyone approving anything:
    through its file tools inside the working directories, a read-only command such as
    ``cat`` (which Claude Code runs without a prompt in every mode), an allowed
    interpreter, or the shell's inherited environment. Move the credential out of reach,
    deny it in the agent's rules *and* its sandbox, or let only a human approve reads."""
    for report in agents_found(snapshot):
        for exposure in exposures_of(snapshot, report.agent):
            item = item_of(snapshot, exposure)
            if exposure.reach is not Reach.NO_APPROVAL or item is None or item.id == _TRANSCRIPTS:
                continue
            if item.severity not in _SERIOUS:
                continue
            yield Finding(
                "IFJ-READ-001",
                Status.FAIL,
                item.severity,
                Confidence.MEDIUM if exposure.uncertain else Confidence.HIGH,
                f"{report.agent.display_name} can read {item.title} without approval",
                (
                    f"Every command the agent runs inherits it: reachable {how(exposure)}."
                    if item.path == ENVIRONMENT
                    else f"{item.path} is reachable {how(exposure)}."
                ),
                agent=report.agent,
                item=item.id,
                sources=item_source(item),
                evidence=item_evidence(item),
                recommended_action=(
                    "Start the agent without these variables, or have its sandbox strip them "
                    "(Claude Code: sandbox credentials.envVars with mode deny)."
                    if item.path == ENVIRONMENT
                    else "Deny it in the agent's rules and enable the sandbox with the same path "
                    "in sandbox.filesystem.denyRead, or move it out of the home directory."
                ),
                verify_command="ifinjected scan",
                limitations=("Uncertain: part of the configuration could not be decided.",)
                if exposure.uncertain
                else (),
            )


@registry.rule(
    "IFJ-READ-002",
    "Credentials are one approval away",
    sources=(CLAUDE_DOCS,),
    max_status=Status.WARN,
)
def after_approval(snapshot: Snapshot) -> Iterator[Finding]:
    """These credentials are readable once someone (or a classifier) approves a single
    action. A human prompt is a real barrier only if every prompt is read: an injected
    agent asks for exactly the action that reads the file, often in a long session where
    approving becomes a reflex. This finding never fails ``--strict`` on its own."""
    for report in agents_found(snapshot):
        pending = []
        for exposure in exposures_of(snapshot, report.agent):
            item = item_of(snapshot, exposure)
            if (
                exposure.reach is Reach.AFTER_APPROVAL
                and item is not None
                and item.severity is Severity.HIGH
            ):
                pending.append((exposure, item))
        if not pending:
            continue
        automated = sum(1 for e, _ in pending if e.gate is not None and e.gate.value == "automated")
        who = "a classifier's" if automated == len(pending) else "one"
        yield Finding(
            "IFJ-READ-002",
            Status.WARN,
            Severity.MEDIUM,
            Confidence.HIGH,
            f"{len(pending)} high-severity credential(s) are {who} approval away from "
            f"{report.agent.display_name}",
            "; ".join(f"{i.title} ({how(e)})" for e, i in pending[:5])
            + ("; …" if len(pending) > 5 else ""),
            agent=report.agent,
            evidence=tuple(Evidence("inventory", "item", i.path) for _, i in pending),
            recommended_action="Deny the credential directories in the agent's rules and its "
            "sandbox, so that no approval can open them.",
            verify_command="ifinjected scan",
        )


@registry.rule("IFJ-READ-003", "A deny rule can be walked around", sources=(CLAUDE_DOCS,))
def bypassable(snapshot: Snapshot) -> Iterator[Finding]:
    """A rule of the agent denies this file, but another way in is open without a human:
    Claude Code's Read deny rules cover its file tools and the commands it recognises,
    not a Python or Node script that opens the file itself, and not MCP servers. The rule
    gives a false sense of safety, which is worse than none. Only an OS sandbox that
    denies the path stops every process."""
    for report in agents_found(snapshot):
        for exposure in exposures_of(snapshot, report.agent):
            item = item_of(snapshot, exposure)
            if exposure.reach is not Reach.BYPASSABLE_RULE or item is None:
                continue
            rule = exposure.bypassed
            yield Finding(
                "IFJ-READ-003",
                Status.FAIL,
                Severity.HIGH,
                Confidence.HIGH,
                f"{report.agent.display_name}'s deny rule for {item.title} can be walked around",
                f"{item.path} is denied by the rule at "
                f"{rule.path}:{rule.line if rule else '?'}, yet reachable {how(exposure)}."
                if rule
                else f"{item.path} is denied by a rule, yet reachable {how(exposure)}.",
                agent=report.agent,
                item=item.id,
                sources=((rule,) if rule else ()) + item_source(item),
                evidence=(
                    *item_evidence(item),
                    Evidence("rule", "pattern", exposure.bypassed_pattern),
                ),
                recommended_action="Enable the sandbox: Claude Code merges Read deny rules into "
                "it, so every process is refused. Remove allow rules for interpreters such as "
                "Bash(python3 *).",
                verify_command="ifinjected scan",
            )


@registry.rule("IFJ-READ-004", "The sandbox reads your credentials", sources=(SANDBOX_DOCS,))
def sandbox_reads(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent runs commands in an OS sandbox, and commands there can still read this
    credential: sandboxes such as Claude Code's allow reading most of the machine,
    ``~/.ssh`` and ``~/.aws`` included, unless told otherwise. With
    ``autoAllowBashIfSandboxed`` (the default) those commands also run without a
    prompt. Turning the sandbox on protects writes and the network, not your secrets."""
    for report in agents_found(snapshot):
        for exposure in exposures_of(snapshot, report.agent):
            item = item_of(snapshot, exposure)
            if item is None or not exposure.sandboxed or not exposure.reach.reachable:
                continue
            if item.severity is not Severity.HIGH or exposure.path.startswith("environment"):
                continue
            yield Finding(
                "IFJ-READ-004",
                Status.FAIL,
                Severity.HIGH,
                Confidence.HIGH,
                f"{report.agent.display_name}'s sandbox lets commands read {item.title}",
                f"{item.path} is reachable {how(exposure)}.",
                agent=report.agent,
                item=item.id,
                sources=item_source(item),
                evidence=item_evidence(item),
                recommended_action="Add the credential's directory to sandbox.filesystem.denyRead "
                "(or a Read deny rule, which the sandbox merges).",
                verify_command="ifinjected prove --run",
            )


@registry.rule(
    "IFJ-READ-005", "Agent transcripts are readable", sources=(CLAUDE_DOCS,), max_status=Status.WARN
)
def transcripts(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent can read its own (or another agent's) transcripts and prompt history.
    They are plain text and keep whatever a tool printed in earlier sessions, including a
    credential that was read once, so a secret can outlive the file it came from."""
    for report in agents_found(snapshot):
        readable = []
        for exposure in exposures_of(snapshot, report.agent):
            item = item_of(snapshot, exposure)
            if item is not None and item.id == _TRANSCRIPTS and exposure.reach.reachable:
                readable.append(item)
        if readable:
            yield Finding(
                "IFJ-READ-005",
                Status.WARN,
                Severity.LOW,
                Confidence.HIGH,
                f"{report.agent.display_name} can read {len(readable)} transcript and "
                "history store(s)",
                "Secrets printed in earlier sessions stay in these files.",
                agent=report.agent,
                evidence=tuple(Evidence("inventory", "item", i.path) for i in readable),
                recommended_action="Clear old transcripts that may hold secrets, and deny the "
                "transcript directories of other agents.",
                verify_command="ifinjected scan",
            )
