"""``ifinjected diff``: does this change widen what coding agents may do?

The agent configuration a repository commits (``.claude/settings.json``, ``.mcp.json``,
``.codex/config.toml``, ``.gemini/settings.json``, ``.cursor/*.json``, ``opencode.json``,
``.github/copilot/settings.json``…) is read at two refs with ``git show REF:path`` and
compared. Anything that hands agents more is a finding: a new allow rule or a wider
mode, a deny rule that is gone, a new MCP server, a new or changed hook, a weaker
sandbox, an environment variable that redirects API traffic. This is the check for a
pull request: a repository is the easiest place to plant agent configuration.

Git runs read-only: ``-c core.fsmonitor=false`` (no repository program can run), no
optional locks, no prompts. Nothing in the working tree is read or written.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ifinjected.agents.base import describe_command, mapping, strings
from ifinjected.models import Confidence, Evidence, Finding, Severity, SourceRef, Status
from ifinjected.parsers.positions import ConfigSyntaxError, Document, parse_json, parse_toml
from ifinjected.rules.engine import Registry
from ifinjected.runner import CommandRunner, Outcome

GIT_TIMEOUT = 15.0
GIT_ENV = {"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
MAX_BYTES = 1_048_576

FILES: dict[str, str] = {
    ".claude/settings.json": "claude",
    ".claude/settings.local.json": "claude",
    ".mcp.json": "mcp",
    ".codex/config.toml": "codex",
    ".gemini/settings.json": "gemini",
    ".cursor/cli.json": "cursor_cli",
    ".cursor/sandbox.json": "cursor_sandbox",
    ".cursor/mcp.json": "mcp",
    "opencode.json": "opencode",
    "opencode.jsonc": "opencode",
    ".opencode/opencode.json": "opencode",
    ".github/copilot/settings.json": "copilot",
    ".github/mcp.json": "mcp",
}
"""Committed agent configuration, by the kind of file it is."""

_REDIRECTS = re.compile(
    r"(?:_BASE_URL|_API_URL|_ENDPOINT|^HTTPS?_PROXY|^ALL_PROXY|^NODE_EXTRA_CA_CERTS)$", re.I
)


class DiffError(Exception):
    """A ref could not be read (exit code 3): not a repository, or an unknown ref."""


def git_show(runner: CommandRunner, repo: Path, ref: str, path: str) -> str | None:
    """The file at ``ref``, or ``None`` when it does not exist there."""
    argv = ["git", "-c", "core.fsmonitor=false", "-C", str(repo), "show", f"{ref}:{path}"]
    result = runner.run(argv, timeout=GIT_TIMEOUT, env_overrides=GIT_ENV)
    if result.ok:
        return result.stdout if len(result.stdout) <= MAX_BYTES else None
    if result.outcome is Outcome.NONZERO and (
        "does not exist" in result.stderr or "exists on disk, but not in" in result.stderr
    ):
        return None
    raise DiffError(
        result.stderr.strip().splitlines()[0]
        if result.stderr.strip()
        else f"git show {ref}:{path} failed"
    )


def resolve(runner: CommandRunner, repo: Path, ref: str) -> str:
    argv = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(repo),
        "rev-parse",
        "--verify",
        "--quiet",
        f"{ref}^{{commit}}",
    ]
    result = runner.run(argv, timeout=GIT_TIMEOUT, env_overrides=GIT_ENV)
    if not result.ok:
        raise DiffError(f"{ref} is not a commit in {repo}")
    return result.stdout.strip()


@dataclass(frozen=True, slots=True)
class Facts:
    """What one committed file says, reduced to comparable sets and values."""

    sets: dict[str, frozenset[str]]
    values: dict[str, str]
    document: Document | None


def _parse(kind: str, text: str | None) -> Document | None:
    if text is None:
        return None
    try:
        return parse_toml(text) if kind == "codex" else parse_json(text, comments=True)
    except ConfigSyntaxError:
        return None


def _get(data: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        data = data.get(part) if isinstance(data, dict) else None
    return data


def _hooks(data: dict[str, Any]) -> frozenset[str]:
    found = set()
    for event, entries in mapping(data.get("hooks")).items():
        for entry in entries if isinstance(entries, list) else []:
            matcher = mapping(entry).get("matcher", "")
            for hook in mapping(entry).get("hooks") or []:
                hook = mapping(hook)
                program, _ = describe_command(hook.get("command"), None)
                found.add(f"{event}({matcher}): {program or hook.get('type', '?')}")
    return frozenset(found)


def facts_of(kind: str, document: Document | None) -> Facts:
    data = mapping(document.data) if document else {}
    sets: dict[str, frozenset[str]] = {}
    values: dict[str, str] = {}

    def put(name: str, value: Any) -> None:
        if value is not None and not isinstance(value, (dict, list)):
            values[name] = str(value).lower() if isinstance(value, bool) else str(value)

    if kind == "claude":
        for key in ("allow", "ask", "deny", "additionalDirectories"):
            sets[f"permissions.{key}"] = frozenset(strings(_get(data, f"permissions.{key}")))
        sets["sandbox.network.allowedDomains"] = frozenset(
            strings(_get(data, "sandbox.network.allowedDomains"))
        )
        sets["sandbox.excludedCommands"] = frozenset(
            strings(_get(data, "sandbox.excludedCommands"))
        )
        sets["hooks"] = _hooks(data)
        sets["env"] = frozenset(mapping(data.get("env")))
        for key in (
            "permissions.defaultMode",
            "sandbox.enabled",
            "sandbox.allowUnsandboxedCommands",
            "enableAllProjectMcpServers",
            "apiKeyHelper",
        ):
            put(key, _get(data, key))
    elif kind == "mcp":
        sets["mcpServers"] = frozenset(mapping(data.get("mcpServers")))
    elif kind == "codex":
        for key in (
            "sandbox_mode",
            "approval_policy",
            "sandbox_workspace_write.network_access",
            "default_permissions",
        ):
            put(key, _get(data, key))
        sets["mcp_servers"] = frozenset(mapping(data.get("mcp_servers")))
    elif kind == "gemini":
        sets["tools.allowed"] = frozenset(strings(_get(data, "tools.allowed")))
        sets["tools.exclude"] = frozenset(strings(_get(data, "tools.exclude")))
        sets["mcpServers"] = frozenset(mapping(data.get("mcpServers")))
        put("tools.sandbox", _get(data, "tools.sandbox"))
        put("general.defaultApprovalMode", _get(data, "general.defaultApprovalMode"))
    elif kind == "cursor_cli":
        sets["permissions.allow"] = frozenset(strings(_get(data, "permissions.allow")))
        sets["permissions.deny"] = frozenset(strings(_get(data, "permissions.deny")))
    elif kind == "cursor_sandbox":
        put("type", data.get("type"))
        put("readBoundary", data.get("readBoundary"))
        sets["networkPolicy.allow"] = frozenset(strings(_get(data, "networkPolicy.allow")))
    elif kind == "opencode":
        permission = data.get("permission")
        if isinstance(permission, str):
            put("permission", permission)
        for tool, action in mapping(permission).items():
            put(f"permission.{tool}", action if isinstance(action, str) else "map")
        sets["mcp"] = frozenset(mapping(data.get("mcp")))
    elif kind == "copilot":
        put("permissionMode", data.get("permissionMode"))
        put("sandbox.enabled", _get(data, "sandbox.enabled"))
        sets["allowedUrls"] = frozenset(strings(data.get("allowedUrls")))
        sets["mcpServers"] = frozenset(mapping(data.get("mcpServers")))
    return Facts(sets, values, document)


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    kind: str
    key: str
    before: str | None
    after: str | None
    line: int | None


_ADDED_WIDENS = {
    "permissions.allow", "permissions.additionalDirectories", "sandbox.network.allowedDomains",
    "sandbox.excludedCommands", "tools.allowed", "networkPolicy.allow", "allowedUrls",
}  # fmt: skip
_REMOVED_WIDENS = {"permissions.deny", "permissions.ask", "tools.exclude"}
_SERVER_SETS = {"mcpServers", "mcp_servers", "mcp"}
_WIDER_VALUES = {
    "permissions.defaultMode": {"bypassPermissions", "auto", "dontAsk", "acceptEdits"},
    "sandbox_mode": {"danger-full-access"},
    "approval_policy": {"never"},
    "sandbox_workspace_write.network_access": {"true"},
    "general.defaultApprovalMode": {"auto_edit", "yolo"},
    "type": {"insecure_none"},
    "readBoundary": {"system"},
    "permissionMode": {"allow-all", "assisted"},
    "enableAllProjectMcpServers": {"true"},
}
_WEAKER_SANDBOX = {
    ("sandbox.enabled", "false"),
    ("sandbox.allowUnsandboxedCommands", "true"),
    ("tools.sandbox", "false"),
}


def compare(path: str, kind: str, base: Facts, head: Facts) -> Iterator[tuple[str, Change]]:
    """(rule id, change) for everything that widens what agents may do."""

    def line(*keys: str) -> int | None:
        return head.document.line(*keys) if head.document else None

    for key, after in head.sets.items():
        before = base.sets.get(key, frozenset())
        added, removed = after - before, before - after
        if key in _ADDED_WIDENS:
            for value in sorted(added):
                yield "IFJ-DIFF-001", Change(path, kind, key, None, value, line(*key.split(".")))
        if key in _REMOVED_WIDENS:
            for value in sorted(removed):
                yield "IFJ-DIFF-002", Change(path, kind, key, value, None, line(*key.split(".")))
        if key in _SERVER_SETS:
            for value in sorted(added):
                yield "IFJ-DIFF-003", Change(path, kind, key, None, value, line(key, value))
        if key == "hooks":
            for value in sorted(added):
                yield "IFJ-DIFF-004", Change(path, kind, key, None, value, line("hooks"))
        if key == "env":
            for value in sorted(added):
                if _REDIRECTS.search(value):
                    yield "IFJ-DIFF-006", Change(path, kind, key, None, value, line("env", value))
    for key in base.sets:
        if key in _REMOVED_WIDENS and key not in head.sets:
            for value in sorted(base.sets[key]):
                yield "IFJ-DIFF-002", Change(path, kind, key, value, None, None)
    for key, new in head.values.items():
        old = base.values.get(key)
        if old == new:
            continue
        if new in _WIDER_VALUES.get(key, set()) or (
            key.startswith("permission") and new == "allow"
        ):
            yield "IFJ-DIFF-001", Change(path, kind, key, old, new, line(*key.split(".")))
        if (key, new) in _WEAKER_SANDBOX:
            yield "IFJ-DIFF-005", Change(path, kind, key, old, new, line(*key.split(".")))
        if key == "apiKeyHelper":
            yield "IFJ-DIFF-004", Change(path, kind, key, "set" if old else None, "set", line(key))


registry = Registry()
_TITLES = {
    "IFJ-DIFF-001": "The change gives agents more permission",
    "IFJ-DIFF-002": "The change removes a deny or ask rule",
    "IFJ-DIFF-003": "The change adds an MCP server",
    "IFJ-DIFF-004": "The change adds or changes a hook or helper",
    "IFJ-DIFF-005": "The change weakens a sandbox",
    "IFJ-DIFF-006": "The change redirects an agent's traffic",
}


@registry.rule("IFJ-DIFF-001", _TITLES["IFJ-DIFF-001"])
def _more(snapshot: object) -> Iterator[Finding]:
    """A pull request adds an allow rule, an extra working directory, an allowed host or
    command, or sets a mode that asks less (``bypassPermissions``, ``danger-full-access``,
    ``never``, ``allow-all``, ``insecure_none``). Every agent that works in the
    repository gets it the moment the change is checked out."""
    yield from ()


@registry.rule("IFJ-DIFF-002", _TITLES["IFJ-DIFF-002"])
def _fewer(snapshot: object) -> Iterator[Finding]:
    """A pull request removes a deny or ask rule (or a Gemini CLI tool exclusion): what was
    refused or asked for runs without a prompt afterwards."""
    yield from ()


@registry.rule("IFJ-DIFF-003", _TITLES["IFJ-DIFF-003"])
def _server(snapshot: object) -> Iterator[Finding]:
    """A pull request adds an MCP server to committed configuration. A local server is a
    program that runs with the user's full access when the agent starts in the
    repository; Claude Code under ``claude -p`` connects project servers without asking."""
    yield from ()


@registry.rule("IFJ-DIFF-004", _TITLES["IFJ-DIFF-004"])
def _hook(snapshot: object) -> Iterator[Finding]:
    """A pull request adds or changes a hook or a helper command (``apiKeyHelper``). It runs
    outside any sandbox, with the user's full access, on every matching event."""
    yield from ()


@registry.rule("IFJ-DIFF-005", _TITLES["IFJ-DIFF-005"])
def _sandbox(snapshot: object) -> Iterator[Finding]:
    """A pull request turns a sandbox off or lets commands leave it."""
    yield from ()


@registry.rule("IFJ-DIFF-006", _TITLES["IFJ-DIFF-006"])
def _redirect(snapshot: object) -> Iterator[Finding]:
    """A pull request sets an environment variable that sends the agent's API or web
    traffic somewhere else (``ANTHROPIC_BASE_URL``, ``HTTPS_PROXY``…): everything the
    agent sends, prompts and file contents included, can be read there."""
    yield from ()


_SEVERITY = {
    "IFJ-DIFF-001": Severity.HIGH,
    "IFJ-DIFF-002": Severity.HIGH,
    "IFJ-DIFF-003": Severity.MEDIUM,
    "IFJ-DIFF-004": Severity.HIGH,
    "IFJ-DIFF-005": Severity.HIGH,
    "IFJ-DIFF-006": Severity.HIGH,
}


def _summary(rule: str, change: Change) -> str:
    where = change.path
    if rule == "IFJ-DIFF-001":
        if change.key in _ADDED_WIDENS:
            return f"{where} allows more: {change.key} gains {change.after}"
        return f"{where} sets {change.key} to {change.after}" + (
            f" (was {change.before})" if change.before else ""
        )
    if rule == "IFJ-DIFF-002":
        return f"{where} drops {change.before} from {change.key}"
    if rule == "IFJ-DIFF-003":
        return f"{where} adds MCP server {change.after}"
    if rule == "IFJ-DIFF-004":
        return f"{where} adds or changes {change.key}: {change.after}"
    if rule == "IFJ-DIFF-005":
        return f"{where} sets {change.key} to {change.after}"
    return f"{where} sets {change.after}, which redirects the agent's traffic"


def diff_findings(runner: CommandRunner, repo: Path, base: str, head: str) -> tuple[Finding, ...]:
    base_sha, head_sha = resolve(runner, repo, base), resolve(runner, repo, head)
    findings = []
    for path, kind in FILES.items():
        before = facts_of(kind, _parse(kind, git_show(runner, repo, base_sha, path)))
        after = facts_of(kind, _parse(kind, git_show(runner, repo, head_sha, path)))
        for rule, change in compare(path, kind, before, after):
            findings.append(
                Finding(
                    rule,
                    Status.FAIL,
                    _SEVERITY[rule],
                    Confidence.HIGH,
                    _summary(rule, change),
                    f"Committed agent configuration changed between {base} and {head}.",
                    sources=(SourceRef(str(repo / path), change.line, change.key),),
                    evidence=(
                        Evidence("diff", "before", change.before),
                        Evidence("diff", "after", change.after),
                    ),
                    recommended_action="Review the change: every agent that works in this "
                    "repository gets it. Ask for it to be dropped if it is not needed.",
                    verify_command=f"ifinjected diff --base {base}",
                )
            )
    return tuple(findings)
