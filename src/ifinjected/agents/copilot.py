"""GitHub Copilot CLI: settings layers, approvals, sandbox, MCP, Claude Code's files.

Copilot CLI asks before running tools and before touching paths outside its trusted
directories, unless tools are allowed or allow-all is on. Its sandbox is off by
default, and when on it injects git and gh credentials unless told not to. Projects
configure it in ``.github/copilot/``, and it also loads ``.mcp.json`` and the hooks of
Claude Code's ``.claude/settings.json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ifinjected.agents.base import (
    AgentReport,
    ConfigLayer,
    Hook,
    McpServer,
    describe_command,
    load_config,
    mapping,
    strings,
)
from ifinjected.agents.gemini import _merge
from ifinjected.files import Kind, stat_entry
from ifinjected.homes import Platform, Scope, agent_locations, copilot_home
from ifinjected.models import AgentId, Policy, SourceRef
from ifinjected.parsers.positions import key_name
from ifinjected.policy.model import (
    Channel,
    ChannelPolicy,
    EffectivePolicy,
    Gate,
    Network,
    SandboxPolicy,
)

AGENT = AgentId.COPILOT_CLI


def inspect_copilot(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    layers: list[ConfigLayer] = []
    unknowns: list[str] = []
    notes: list[str] = []
    locations = agent_locations(AGENT, p, workspace)
    merged: dict[str, Any] = {}
    servers: list[McpServer] = []
    hooks: list[Hook] = []
    for loc in locations:
        if loc.role not in {"settings", "mcp", "claude_settings", "permissions"}:
            continue
        loaded = load_config(loc.path, policy.max_file_bytes, kind="jsonc")
        if not loaded.exists:
            continue
        layers.append(ConfigLayer(AGENT, loc.scope, str(loc.path), True, None, loaded.problem))
        if loaded.document is None:
            unknowns.append(f"{loc.path} could not be read: {loaded.problem}")
            continue
        data = mapping(loaded.document.data)
        if loc.role == "settings":
            _merge(merged, data)  # user first, then repository and local settings
        elif loc.role == "mcp":
            for name, spec in mapping(data.get("mcpServers")).items():
                if any(s.name == name for s in servers):
                    continue
                spec = mapping(spec)
                program, package = describe_command(spec.get("command"), spec.get("args"))
                url = spec.get("url")
                servers.append(
                    McpServer(
                        AGENT,
                        name,
                        loc.scope,
                        "stdio" if spec.get("command") else "http" if url else "unknown",
                        program,
                        package,
                        urlsplit(url).hostname if isinstance(url, str) else None,
                        tuple(sorted(mapping(spec.get("env")))),
                        tuple(sorted(mapping(spec.get("headers")))),
                        True,
                        SourceRef(
                            str(loc.path),
                            loaded.document.line("mcpServers", name),
                            key_name(("mcpServers", name)),
                        ),
                    )
                )
        elif loc.role == "claude_settings":
            for event, entries in mapping(data.get("hooks")).items():
                for entry in entries if isinstance(entries, list) else []:
                    for hook in mapping(entry).get("hooks") or []:
                        hook = mapping(hook)
                        program, _ = describe_command(hook.get("command"), None)
                        if hook.get("type") == "command" and program:
                            hooks.append(
                                Hook(
                                    AGENT,
                                    event,
                                    program,
                                    Scope.PROJECT,
                                    SourceRef(str(loc.path), loaded.document.line("hooks", event)),
                                )
                            )
        elif loc.role == "permissions":
            unknowns.append("persisted tool approvals in permissions-config.json are not modelled")
    mode = str(merged.get("permissionMode") or merged.get("defaultMode") or "manual")
    allow_all = mode in {"allow-all", "autopilot"}
    sandbox_cfg = mapping(merged.get("sandbox"))
    sandbox_on = sandbox_cfg.get("enabled") is True
    user_policy = mapping(sandbox_cfg.get("userPolicy"))
    network = mapping(user_policy.get("network"))
    allowed_hosts = tuple(strings(network.get("allowedHosts")))
    denied = tuple(strings(mapping(user_policy.get("filesystem")).get("deniedPaths")))
    auth = mapping(sandbox_cfg.get("auth"))
    injects = [name for name in ("git", "gh") if auth.get(name) is not False]
    sandbox = SandboxPolicy(
        enabled=sandbox_on,
        available=None,
        read_deny=tuple(str(p.home / d[2:]) if d.startswith("~/") else d for d in denied),
        network=Network.ALLOWLIST if allowed_hosts else Network.UNKNOWN,
        allowed_domains=allowed_hosts,
        escape_hatches=("sandbox.allowBypass",)
        if sandbox_on and sandbox_cfg.get("allowBypass") is not False
        else (),
    )
    shell_gate = Gate.NONE if allow_all else Gate.AUTOMATED if mode == "assisted" else Gate.HUMAN
    channels = [
        ChannelPolicy(
            Channel.FILE_TOOL,
            Gate.NONE,
            Gate.NONE if allow_all else Gate.HUMAN,
            note="file reads, inside trusted directories without asking",
        ),
        ChannelPolicy(
            Channel.SHELL_ARBITRARY,
            shell_gate,
            shell_gate,
            sandboxed=sandbox_on,
            note="shell commands",
        ),
    ]
    if sandbox_on and sandbox_cfg.get("allowBypass") is not False:
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                Gate.HUMAN,
                Gate.HUMAN,
                sandboxed=False,
                note="a command run outside the sandbox (allowBypass)",
            )
        )
    if sandbox_on and injects:
        notes.append(
            f"the sandbox is given your {' and '.join(injects)} credentials (sandbox.auth)"
        )
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=(str(workspace),) if workspace is not None else (),
        channels=tuple(channels),
        sandbox=sandbox,
        unknowns=tuple(unknowns),
        web_fetch=Gate.NONE if allow_all else Gate.HUMAN,
        mcp_gates=tuple((s.name, Gate.NONE if allow_all else Gate.HUMAN) for s in servers),
    )
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("permission mode", mode, None),
        ("sandbox", "on" if sandbox_on else "off", None),
    ]
    if sandbox_on:
        settings.append(("credentials given to the sandbox", ", ".join(injects) or "none", None))
    found = bool(layers) or stat_entry(copilot_home(p)).kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode=mode,
        mcp_servers=tuple(servers),
        hooks=tuple(hooks),
        settings=tuple(settings),
        notes=tuple(notes),
        facts=("copilot.files", "copilot.sandbox", "copilot.approvals"),
    )
