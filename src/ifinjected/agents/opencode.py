"""opencode: configuration precedence, last-match permissions, MCP servers.

opencode has no OS sandbox, and most permissions default to ``allow``: shell commands
and web fetches run without a prompt unless the configuration says otherwise. Reads ask
for ``.env`` files, and anything outside the working directory asks
(``external_directory``). Rules in a pattern map are matched in order and the last
match wins. Configuration files, least authoritative first: the user's, the file named
by ``OPENCODE_CONFIG``, the project's, and the managed one.
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
)
from ifinjected.agents.gemini import _merge
from ifinjected.files import Kind, stat_entry
from ifinjected.homes import Platform, Scope, agent_locations, opencode_config_dir
from ifinjected.models import AgentId, Policy, SourceRef
from ifinjected.parsers.positions import key_name
from ifinjected.policy.model import (
    Channel,
    ChannelPolicy,
    EffectivePolicy,
    Gate,
    Network,
    Precedence,
    ReadRule,
    SandboxPolicy,
)

AGENT = AgentId.OPENCODE
_ACTIONS = {"allow": Gate.NONE, "ask": Gate.HUMAN, "deny": Gate.DENIED}
_DEFAULT_READ = (("*", "allow"), ("*.env", "ask"), ("*.env.*", "ask"), ("*.env.example", "allow"))
_INTERPRETERS = re.compile(
    r"^(?:\*|python[0-9.]*|node|deno|bun|ruby|perl|php|bash|sh|zsh|env|npx|uvx|uv|npm|pnpm|yarn|"
    r"make|docker|curl|wget|xargs)\b"
)


def _gate(value: Any, default: Gate) -> Gate:
    return _ACTIONS.get(value, default) if isinstance(value, str) else default


def _tool(permission: Any, tool: str) -> Any:
    if isinstance(permission, str):
        return permission
    return mapping(permission).get(tool)


def _map_gate(value: Any, default: Gate, opens: re.Pattern[str]) -> Gate:
    """The gate of a tool whose permission is an action or a pattern map: the action of
    the last pattern that lets an arbitrary command through, else the catch-all."""
    if isinstance(value, str):
        return _gate(value, default)
    if not isinstance(value, dict):
        return default
    result = default
    for pattern, action in value.items():
        if pattern == "*":
            result = _gate(action, default)
    for pattern, action in value.items():
        if pattern != "*" and opens.match(pattern) and _gate(action, default) is Gate.NONE:
            return Gate.NONE
    return result


def inspect_opencode(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    layers: list[ConfigLayer] = []
    unknowns: list[str] = []
    merged: dict[str, Any] = {}
    servers: list[McpServer] = []
    order = [
        (Scope.USER, loc.path)
        for loc in agent_locations(AGENT, p)
        if loc.role == "config" and loc.scope is Scope.USER
    ]
    if workspace is not None:
        order += [(Scope.PROJECT, workspace / name) for name in ("opencode.json", "opencode.jsonc")]
        order += [
            (Scope.PROJECT, workspace / ".opencode" / name)
            for name in ("opencode.json", "opencode.jsonc")
        ]
    order += [
        (Scope.MANAGED, loc.path) for loc in agent_locations(AGENT, p) if loc.scope is Scope.MANAGED
    ]
    for scope, path in order:
        loaded = load_config(path, policy.max_file_bytes, kind="jsonc")
        if not loaded.exists:
            continue
        layers.append(ConfigLayer(AGENT, scope, str(path), True, None, loaded.problem))
        if loaded.document is None:
            unknowns.append(f"{path} could not be read: {loaded.problem}")
            continue
        data = mapping(loaded.document.data)
        _merge(merged, data)
        mcp = mapping(data.get("mcp"))
        root: tuple[str, ...] = ("mcp",)
        nested = mapping(mcp.get("servers"))
        if (
            nested
            and all(isinstance(v, dict) for v in nested.values())
            and not {"command", "url", "type"} & set(nested)
        ):
            mcp, root = nested, ("mcp", "servers")
        for name, spec in mcp.items():
            spec = mapping(spec)
            if not spec or any(s.name == name for s in servers):
                continue
            program, package = describe_command(spec.get("command"), None)
            url = spec.get("url")
            servers.append(
                McpServer(
                    agent=AGENT,
                    name=name,
                    scope=scope,
                    transport="stdio" if spec.get("command") else "http" if url else "unknown",
                    program=program,
                    package=package,
                    host=urlsplit(url).hostname if isinstance(url, str) else None,
                    env_names=tuple(sorted(mapping(spec.get("environment") or spec.get("env")))),
                    header_names=tuple(sorted(mapping(spec.get("headers")))),
                    approved=spec.get("enabled") is not False,
                    source=SourceRef(
                        str(path), loaded.document.line(*root, name), key_name((*root, name))
                    ),
                )
            )
    permission = merged.get("permission", {})
    external = _gate(_tool(permission, "external_directory"), Gate.HUMAN)
    read_value = _tool(permission, "read")
    read_map = (
        list(read_value.items())
        if isinstance(read_value, dict)
        else ([("*", read_value)] if isinstance(read_value, str) else list(_DEFAULT_READ))
    )
    # Read rules decide inside the working directory; outside it, external_directory
    # decides first (a read there needs both), so rules are anchored to the workspace.
    rules = []
    if workspace is not None:
        for pattern, action in read_map:
            anchored = str(workspace) if pattern == "*" else str(workspace / "**" / pattern)
            rules.append(
                ReadRule(anchored, _gate(action, Gate.NONE), frozenset({Channel.FILE_TOOL}))
            )
    bash = _map_gate(_tool(permission, "bash"), Gate.NONE, _INTERPRETERS)
    channels = [
        ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, external, note="read, glob and grep tools"),
    ]
    if bash is not Gate.DENIED:
        channels.append(
            ChannelPolicy(
                Channel.SHELL_RECOGNIZED,
                Gate.NONE,
                max(bash, external, key=list(Gate).index),
                note="bash commands that name a path, such as cat",
            )
        )
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY, bash, bash, note="bash commands that open files themselves"
            )
        )
    mcp_gate = _gate(permission, Gate.NONE) if isinstance(permission, str) else Gate.NONE
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=(str(workspace),) if workspace is not None else (),
        channels=tuple(channels),
        rules=tuple(rules),
        precedence=Precedence.LAST_MATCH,
        sandbox=SandboxPolicy(enabled=False, network=Network.OPEN),
        unknowns=tuple(unknowns),
        web_fetch=_gate(_tool(permission, "webfetch"), Gate.NONE),
        web_search=_gate(_tool(permission, "websearch"), Gate.NONE),
        mcp_gates=tuple((s.name, mcp_gate) for s in servers if s.approved is not False),
    )
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("bash", {Gate.NONE: "allow", Gate.HUMAN: "ask", Gate.DENIED: "deny"}.get(bash, "?"), None),
        (
            "outside the working directory",
            {Gate.NONE: "allow", Gate.HUMAN: "ask", Gate.DENIED: "deny"}.get(external, "?"),
            None,
        ),
        ("sandbox", "none (opencode has no OS sandbox)", None),
    ]
    found = bool(layers) or stat_entry(opencode_config_dir(p)).kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode="default",
        mcp_servers=tuple(servers),
        settings=tuple(settings),
        notes=("opencode --auto approves every request that is not explicitly denied",),
        facts=(
            "opencode.defaults",
            "opencode.last_match",
            "opencode.external",
            "opencode.no_sandbox",
        ),
    )
