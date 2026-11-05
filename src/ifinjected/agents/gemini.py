"""Gemini CLI: settings layers, approval modes, tool lists, sandbox, trust, MCP.

Settings layers, least authoritative first: system defaults, user settings, project
settings (ignored in an untrusted folder when folder trust is on), and the system
override. File tools stay inside the workspace root; shell commands ask unless allowed;
``web_fetch`` asks. The sandbox is off by default; on macOS its default Seatbelt profile
still reads every file and reaches the network, while Docker and Podman sandboxes see
only what is mounted.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ifinjected.agents.base import (
    AgentReport,
    ConfigLayer,
    Loaded,
    McpServer,
    describe_command,
    load_config,
    mapping,
    strings,
)
from ifinjected.files import Kind, list_directory, stat_entry
from ifinjected.homes import Platform, Scope, agent_locations
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

AGENT = AgentId.GEMINI_CLI
_SHELL = "run_shell_command"
_INTERPRETERS = re.compile(
    r"^(?:python[0-9.]*|node|deno|bun|ruby|perl|php|bash|sh|zsh|env|npx|uvx|uv|npm|pnpm|yarn|"
    r"make|docker|curl|wget|cat|xargs)$"
)


def _merge(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Deep merge, ``source`` winning; lists are combined."""
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        elif isinstance(value, list) and isinstance(target.get(key), list):
            target[key] = [*target[key], *[v for v in value if v not in target[key]]]
        else:
            target[key] = value


def _setting(data: dict[str, Any], *paths: str) -> Any:
    """The first of ``paths`` (dotted, v2 nested or v1 flat names) that is set."""
    for dotted in paths:
        value: Any = data
        for part in dotted.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is not None:
            return value
    return None


def _trusted(
    p: Platform, workspace: Path | None, policy: Policy, layers: list[ConfigLayer]
) -> bool | None:
    """Whether the workspace is trusted, from ~/.gemini/trustedFolders.json."""
    if workspace is None:
        return None
    path = p.home / ".gemini" / "trustedFolders.json"
    loaded = load_config(path, policy.max_file_bytes)
    if loaded.exists:
        layers.append(ConfigLayer(AGENT, Scope.USER, str(path), True, None, loaded.problem))
    rules = mapping(loaded.document.data) if loaded.document else {}
    verdict: bool | None = None
    for folder, rule in rules.items():
        folder_path = Path(folder)
        if (
            rule == "TRUST_FOLDER"
            and (workspace == folder_path or folder_path in workspace.parents)
        ) or (
            rule == "TRUST_PARENT"
            and (folder_path.parent == workspace or folder_path.parent in workspace.parents)
        ):
            verdict = True
        elif rule == "DO_NOT_TRUST" and workspace == folder_path:
            return False
    return verdict if verdict is not None else False


def _policy_rules(p: Platform, policy: Policy, layers: list[ConfigLayer]) -> tuple[bool, bool]:
    """(shell denied entirely, broad shell commands allowed) from policy engine files."""
    denied = allowed = False
    directories = [loc.path for loc in agent_locations(AGENT, p) if loc.role == "policies"]
    for directory in directories:
        for name in list_directory(directory) or []:
            if not name.endswith(".toml"):
                continue
            loaded = load_config(directory / name, policy.max_file_bytes, kind="toml")
            layers.append(
                ConfigLayer(AGENT, Scope.USER, str(loaded.path), True, None, loaded.problem)
            )
            if loaded.document is None:
                continue
            for rule in mapping(loaded.document.data).get("rule", []) or []:
                rule = mapping(rule)
                if rule.get("toolName") != _SHELL:
                    continue
                prefix = rule.get("commandPrefix")
                if rule.get("decision") == "deny" and prefix is None:
                    denied = True
                if rule.get("decision") == "allow" and (
                    prefix is None
                    or (
                        isinstance(prefix, str)
                        and _INTERPRETERS.match(prefix.split()[0] if prefix.split() else "")
                    )
                ):
                    allowed = True
    return denied, allowed


def _shell_allowed(entries: list[str]) -> bool:
    for entry in entries:
        if entry == _SHELL:
            return True
        match = re.match(rf"^{_SHELL}\((.*)\)$", entry)
        if match and _INTERPRETERS.match(
            match.group(1).split()[0] if match.group(1).split() else ""
        ):
            return True
    return False


def inspect_gemini(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    locations = agent_locations(AGENT, p, workspace)
    by_role = {(loc.role, loc.scope): loc.path for loc in locations}
    layers: list[ConfigLayer] = []
    unknowns: list[str] = []
    notes: list[str] = []

    def load(role: str, scope: Scope) -> Loaded | None:
        path = by_role.get((role, scope))
        if path is None:
            return None
        loaded = load_config(path, policy.max_file_bytes, kind="jsonc")
        if loaded.exists:
            layers.append(ConfigLayer(AGENT, scope, str(path), True, None, loaded.problem))
            if loaded.problem:
                unknowns.append(f"{path} could not be read: {loaded.problem}")
        return loaded

    defaults = load("system_defaults", Scope.SYSTEM)
    user = load("settings", Scope.USER)
    project = load("settings", Scope.PROJECT) if workspace is not None else None
    override = load("system_override", Scope.MANAGED)
    merged: dict[str, Any] = {}
    for loaded in (defaults, user):
        if loaded is not None and loaded.document is not None:
            _merge(merged, mapping(loaded.document.data))
    folder_trust = _setting(merged, "security.folderTrust.enabled", "folderTrust") is True
    if override is not None and override.document is not None:
        folder_trust = (
            _setting(mapping(override.document.data), "security.folderTrust.enabled") is True
            or folder_trust
        )
    trusted = _trusted(p, workspace, policy, layers) if folder_trust else None
    if project is not None and project.document is not None:
        if trusted is False:
            for index, layer in enumerate(layers):
                if layer.path == str(project.path):
                    layers[index] = ConfigLayer(
                        AGENT, Scope.PROJECT, layer.path, True, False, layer.skipped
                    )
        else:
            _merge(merged, mapping(project.document.data))
    if override is not None and override.document is not None:
        _merge(merged, mapping(override.document.data))

    mode = str(_setting(merged, "general.defaultApprovalMode") or "default")
    core = strings(_setting(merged, "tools.core", "coreTools"))
    excluded = strings(_setting(merged, "tools.exclude", "excludeTools"))
    allowed = strings(_setting(merged, "tools.allowed", "allowedTools"))
    policy_denied, policy_allowed = _policy_rules(p, policy, layers)
    shell_removed = (
        policy_denied
        or _SHELL in excluded
        or (bool(core) and not any(c.startswith(_SHELL) for c in core))
    )
    shell_gate = Gate.NONE if _shell_allowed(allowed) or policy_allowed else Gate.HUMAN
    sandbox_setting = _setting(merged, "tools.sandbox", "sandbox")
    env_sandbox = (p.env_value("GEMINI_SANDBOX") or "").strip().lower()
    kind: str | None = None
    if env_sandbox and env_sandbox not in {"false", "0"}:
        kind = env_sandbox if env_sandbox not in {"true", "1"} else "default"
    elif sandbox_setting is True:
        kind = "default"
    elif isinstance(sandbox_setting, str) and sandbox_setting:
        kind = sandbox_setting
    if kind == "default":
        kind = "sandbox-exec" if p.system.value == "macos" else "docker"
    container = kind in {"docker", "podman"}
    sandbox = SandboxPolicy(
        enabled=kind is not None,
        available=True if kind == "sandbox-exec" else None,
        read_only=(str(workspace),) if container and workspace is not None else None,
        network=Network.OPEN if kind is not None else Network.UNKNOWN,
    )
    channels = [
        ChannelPolicy(
            Channel.FILE_TOOL,
            Gate.NONE,
            Gate.DENIED,
            note="read_file, grep and glob, inside the workspace root",
        )
    ]
    if not shell_removed:
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                shell_gate,
                shell_gate,
                sandboxed=kind is not None,
                note="run_shell_command (bash -c)",
            )
        )
    servers: list[McpServer] = []
    gates: list[tuple[str, Gate]] = []
    for loaded, scope in (
        (user, Scope.USER),
        (project if trusted is not False else None, Scope.PROJECT),
        (override, Scope.MANAGED),
        (defaults, Scope.SYSTEM),
    ):
        if loaded is None or loaded.document is None:
            continue
        for name, spec in mapping(mapping(loaded.document.data).get("mcpServers")).items():
            if any(s.name == name for s in servers):
                continue
            spec = mapping(spec)
            program, package = describe_command(spec.get("command"), spec.get("args"))
            url = spec.get("httpUrl") or spec.get("url")
            host = urlsplit(url).hostname if isinstance(url, str) else None
            line = loaded.document.line("mcpServers", name)
            servers.append(
                McpServer(
                    AGENT,
                    name,
                    scope,
                    "stdio" if spec.get("command") else "http" if url else "unknown",
                    program,
                    package,
                    host,
                    tuple(sorted(mapping(spec.get("env")))),
                    tuple(sorted(mapping(spec.get("headers")))),
                    True,
                    SourceRef(str(loaded.path), line, key_name(("mcpServers", name))),
                )
            )
            gates.append((name, Gate.NONE if spec.get("trust") is True else Gate.HUMAN))
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=(str(workspace),) if workspace is not None else (),
        channels=tuple(channels),
        sandbox=sandbox,
        unknowns=tuple(unknowns),
        web_fetch=Gate.HUMAN,
        web_search=Gate.NONE,
        mcp_gates=tuple(gates),
    )
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("approval mode", mode, None),
        ("sandbox", kind or "off", None),
        ("folder trust", "on" if folder_trust else "off", None),
    ]
    if folder_trust and workspace is not None:
        settings.append(("workspace trusted", "yes" if trusted else "no", None))
    if allowed:
        settings.append(("tools.allowed", ", ".join(allowed), None))
    if kind in {"docker", "podman"}:
        notes.append(
            f"the {kind} sandbox sees only mounted directories; "
            "whether it can start here is not checked"
        )
    if mode == "plan":
        notes.append("plan mode asks before every web fetch")
    found = bool(layers) or stat_entry(p.home / ".gemini").kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode=mode,
        mcp_servers=tuple(servers),
        settings=tuple(settings),
        notes=tuple(notes),
        facts=(
            "gemini.files",
            "gemini.shell",
            "gemini.web_fetch",
            "gemini.sandbox",
            "gemini.trust",
            "gemini.mcp_trust",
        ),
    )
