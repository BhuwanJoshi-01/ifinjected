"""Cursor (IDE agent and CLI): run mode, read access, sandbox.json, permissions, MCP.

Cursor's recommended default run mode is Auto-review: allowlisted calls run at once,
other shell commands run in the sandbox when possible, and a classifier reviews the
rest. Read Access defaults to *System*, so files outside the workspace are read without
approval, and the sandbox's default network allowlist includes ``github.com``. The IDE
keeps its run mode in its own state, which is not read here; the CLI's ``approvalMode``
in ``cli-config.json`` is.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ifinjected.agents.base import (
    AgentReport,
    ConfigLayer,
    McpServer,
    describe_command,
    load_config,
    mapping,
    strings,
)
from ifinjected.agents.gemini import _merge
from ifinjected.files import Kind, stat_entry
from ifinjected.homes import Platform, Scope, System, agent_locations, cursor_dir
from ifinjected.models import AgentId, Policy, SourceRef
from ifinjected.parsers.positions import key_name
from ifinjected.policy.model import (
    Channel,
    ChannelPolicy,
    EffectivePolicy,
    Gate,
    Network,
    ReadRule,
    SandboxPolicy,
)

AGENT = AgentId.CURSOR
_MODES = {"auto-review": "auto-review", "allowlist": "allowlist", "unrestricted": "run-everything"}
_TOKEN = re.compile(r"^(Shell|Read|Write|WebFetch|Mcp)\((.*)\)$")
_INTERPRETERS = re.compile(
    r"^(?:\*|python[0-9.]*|node|bash|sh|zsh|npx|uvx|uv|npm|pnpm|yarn|make|docker|curl)\b"
)
_DEFAULT_ALLOWED = ("github.com", "pypi.org", "npmjs.com")
"""Part of the ~100 domains Cursor allows by default; enough to show the upload host."""


def _anchor(glob: str, p: Platform, workspace: Path | None) -> str | None:
    if glob.startswith("~/"):
        return str(p.home / glob[2:])
    if glob.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", glob):
        return glob
    if workspace is None:
        return None
    return str(workspace / "**" / glob) if "/" not in glob.strip("/") else str(workspace / glob)


def inspect_cursor(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    layers: list[ConfigLayer] = []
    unknowns: list[str] = []
    by_role: dict[str, list[tuple[Scope, Path]]] = {}
    for loc in agent_locations(AGENT, p, workspace):
        by_role.setdefault(loc.role, []).append((loc.scope, loc.path))

    def merged_files(role: str) -> tuple[dict[str, Any], list[tuple[Scope, Any]]]:
        merged: dict[str, Any] = {}
        loaded_all = []
        for scope, path in by_role.get(role, []):  # user first, project last: it wins
            loaded = load_config(path, policy.max_file_bytes, kind="jsonc")
            if not loaded.exists:
                continue
            layers.append(ConfigLayer(AGENT, scope, str(path), True, None, loaded.problem))
            if loaded.document is None:
                unknowns.append(f"{path} could not be read: {loaded.problem}")
                continue
            _merge(merged, mapping(loaded.document.data))
            loaded_all.append((scope, loaded))
        return merged, loaded_all

    cli, _ = merged_files("cli_config")
    sandbox_cfg, _ = merged_files("sandbox")
    _, mcp_files = merged_files("mcp")
    permissions = mapping(cli.get("permissions"))
    allow, deny = strings(permissions.get("allow")), strings(permissions.get("deny"))
    mode_setting = cli.get("approvalMode")
    mode = _MODES.get(str(mode_setting), "auto-review") if mode_setting else "auto-review"
    if not mode_setting:
        unknowns.append(
            "the IDE's run mode is kept in Cursor's own state; Auto-review, the default, is assumed"
        )
    kind = str(
        sandbox_cfg.get("type") or mapping(cli.get("sandbox")).get("mode") or "workspace_readwrite"
    )
    boundary = str(
        sandbox_cfg.get("readBoundary")
        or mapping(cli.get("sandbox")).get("readBoundary")
        or "system"
    )
    network = mapping(sandbox_cfg.get("networkPolicy"))
    sandbox_on = kind != "insecure_none" and mode != "run-everything"
    available: bool | None = True if p.system is System.MACOS else None
    if sandbox_on and p.system is System.LINUX:
        unknowns.append(
            "Cursor's sandbox needs Linux 6.2+ with Landlock v3; without it, commands ask first"
        )
    if p.system is System.WINDOWS:
        available = None
    allowed_domains = tuple(strings(network.get("allow"))) or _DEFAULT_ALLOWED
    sandbox = SandboxPolicy(
        enabled=sandbox_on,
        available=available,
        read_only=(str(workspace),) if boundary == "workspace" and workspace is not None else None,
        network=Network.OPEN if network.get("default") == "allow" else Network.ALLOWLIST,
        allowed_domains=allowed_domains,
    )

    def has(tokens: list[str], tool: str, pattern: re.Pattern[str] | None = None) -> bool:
        for token in tokens:
            match = _TOKEN.match(token)
            if (
                match
                and match.group(1) == tool
                and (pattern is None or pattern.match(match.group(2)))
            ):
                return True
        return False

    rules = []
    for tokens, gate in ((deny, Gate.DENIED), (allow, Gate.NONE)):
        for token in tokens:
            match = _TOKEN.match(token)
            if match and match.group(1) == "Read":
                anchored = _anchor(match.group(2), p, workspace)
                if anchored:
                    rules.append(ReadRule(anchored, gate, frozenset({Channel.FILE_TOOL})))
    if mode == "run-everything":
        file_gate = shell_gate = other_gate = Gate.NONE
    else:
        file_gate = Gate.NONE if boundary == "system" else Gate.HUMAN
        shell_gate = Gate.NONE if sandbox_on else Gate.HUMAN
        other_gate = Gate.AUTOMATED if mode == "auto-review" else Gate.HUMAN
        if has(allow, "Shell", _INTERPRETERS):
            shell_gate = Gate.NONE
    channels = [
        ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, file_gate, note="the agent's file reads")
    ]
    if not has(deny, "Shell", re.compile(r"^\*?$")):
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                shell_gate,
                shell_gate,
                sandboxed=sandbox_on,
                note="terminal commands" + (" in the sandbox" if sandbox_on else ""),
            )
        )
        if sandbox_on:
            channels.append(
                ChannelPolicy(
                    Channel.SHELL_ARBITRARY,
                    other_gate,
                    other_gate,
                    sandboxed=False,
                    note="a command that cannot run sandboxed, after review",
                )
            )
    servers: list[McpServer] = []
    gates = []
    for scope, loaded in reversed(mcp_files):
        for name, spec in mapping(mapping(loaded.document.data).get("mcpServers")).items():
            if any(s.name == name for s in servers):
                continue
            spec = mapping(spec)
            program, package = describe_command(spec.get("command"), spec.get("args"))
            url = spec.get("url")
            servers.append(
                McpServer(
                    AGENT,
                    name,
                    scope,
                    "stdio" if spec.get("command") else "http" if url else "unknown",
                    program,
                    package,
                    urlsplit(url).hostname if isinstance(url, str) else None,
                    tuple(sorted(mapping(spec.get("env")))),
                    tuple(sorted(mapping(spec.get("headers")))),
                    True,
                    SourceRef(
                        str(loaded.path),
                        loaded.document.line("mcpServers", name),
                        key_name(("mcpServers", name)),
                    ),
                )
            )
            allowed = (
                has(allow, "Mcp", re.compile(rf"^{re.escape(name)}(:\*)?$"))
                or mode == "run-everything"
            )
            gates.append((name, Gate.NONE if allowed else other_gate))
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=(str(workspace),) if workspace is not None else (),
        channels=tuple(channels),
        rules=tuple(rules),
        sandbox=sandbox,
        unknowns=tuple(unknowns),
        web_fetch=Gate.NONE
        if has(allow, "WebFetch", re.compile(r"^\*?$")) or mode == "run-everything"
        else other_gate,
        mcp_gates=tuple(gates),
    )
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("run mode", mode + ("" if mode_setting else " (assumed default)"), None),
        ("read access", boundary, None),
        ("sandbox", kind if sandbox_on else "off", None),
        (
            "network allowlist",
            ", ".join(allowed_domains) + (" …" if not network.get("allow") else ""),
            None,
        ),
    ]
    found = bool(layers) or stat_entry(cursor_dir(p)).kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode=mode,
        mcp_servers=tuple(servers),
        settings=tuple(settings),
        facts=(
            "cursor.default_mode",
            "cursor.read_access",
            "cursor.network",
            "cursor.platforms",
            "cursor.sandbox_json",
            "cursor.run_everything",
        ),
    )
