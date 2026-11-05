"""Claude Code: settings layers, trust, permission modes and rules, sandbox, MCP, hooks.

Everything here follows Claude Code's documentation (``agents/data.json`` cites each
fact). The layers, most authoritative first: managed settings (``managed-settings.json``
and ``managed-settings.d/*.json``), local project settings, project settings, user
settings. List settings (permission rules, additional directories) merge across layers;
for other keys the most authoritative layer wins. ``auto`` and ``bypassPermissions`` are
ignored as a default mode in project and local files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from ifinjected.agents.base import (
    AgentReport,
    ConfigLayer,
    Hook,
    Loaded,
    McpServer,
    describe_command,
    load_config,
    mapping,
    strings,
)
from ifinjected.files import Kind, list_directory, stat_entry
from ifinjected.homes import Platform, Scope, System, claude_config_dir, claude_managed_dir
from ifinjected.homes import claude_state_file as _state_file
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

AGENT = AgentId.CLAUDE_CODE
MAX_STATE_BYTES = 16 * 1024 * 1024
"""~/.claude.json grows with every project; it is configuration, read whole and capped."""

_MODES = ("default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions")
_MODE_ALIASES = {"manual": "default"}
_PROJECT_IGNORED_MODES = frozenset({"auto", "bypassPermissions"})
_RULE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\((.*)\))?\s*$", re.DOTALL)
_FILE_CHANNELS = frozenset({Channel.FILE_TOOL, Channel.SHELL_RECOGNIZED})

# Bash allow rules that let a command open any file it likes: interpreters, script
# runners and shells. A rule like Bash(python3 *) means `python3 -c "open(...)"` runs
# without a prompt, and no Read rule sees the file it opens.
_ARBITRARY = re.compile(
    r"^(?:\*|(?:sudo\s+)?(?:python[0-9.]*|node|deno|bun|ruby|perl|php|lua|R|Rscript|julia|"
    r"bash|sh|zsh|fish|dash|pwsh|powershell|env|xargs|eval|exec|source|uv\s+run|uvx|npx|"
    r"bunx|pnpm|yarn|npm\s+(?:run|exec|x)|make|just|cargo\s+run|go\s+run|docker|podman|"
    r"kubectl\s+exec|ssh|scp|rsync|awk|gawk|curl|wget)\b)"
)


@dataclass(slots=True)
class _Merged:
    allow: list[tuple[str, Scope, SourceRef]] = field(default_factory=list)
    ask: list[tuple[str, Scope, SourceRef]] = field(default_factory=list)
    deny: list[tuple[str, Scope, SourceRef]] = field(default_factory=list)
    additional: list[tuple[str, Scope, SourceRef]] = field(default_factory=list)
    scalars: dict[str, tuple[Any, Scope, SourceRef]] = field(default_factory=dict)
    sandbox_lists: dict[str, list[tuple[str, Scope, SourceRef]]] = field(default_factory=dict)
    hooks: list[Hook] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)


def _layer_paths(p: Platform, workspace: Path | None) -> list[tuple[Scope, Path]]:
    managed = claude_managed_dir(p)
    layers: list[tuple[Scope, Path]] = [(Scope.MANAGED, managed / "managed-settings.json")]
    dropins = list_directory(managed / "managed-settings.d") or []
    layers += [
        (Scope.MANAGED, managed / "managed-settings.d" / name)
        for name in dropins
        if name.endswith(".json")
    ]
    if workspace is not None:
        layers.append((Scope.LOCAL, workspace / ".claude" / "settings.local.json"))
        layers.append((Scope.PROJECT, workspace / ".claude" / "settings.json"))
    layers.append((Scope.USER, claude_config_dir(p) / "settings.json"))
    return layers


def _source(loaded: Loaded, *path: str | int) -> SourceRef:
    line = loaded.document.line(*path) if loaded.document else None
    return SourceRef(str(loaded.path), line, key_name(tuple(path)) if path else None)


def _scalar(merged: _Merged, key: str, value: Any, scope: Scope, src: SourceRef) -> None:
    if key not in merged.scalars:  # layers come most authoritative first
        merged.scalars[key] = (value, scope, src)


def _merge_layer(merged: _Merged, loaded: Loaded, scope: Scope, trusted: bool) -> None:
    if loaded.document is None:
        return
    data = mapping(loaded.document.data)
    permissions = mapping(data.get("permissions"))
    project = scope in {Scope.PROJECT, Scope.LOCAL}
    for kind, target in (("allow", merged.allow), ("ask", merged.ask), ("deny", merged.deny)):
        if kind == "allow" and project and not trusted:
            continue  # project allow rules wait for workspace trust
        for index, rule in enumerate(strings(permissions.get(kind))):
            target.append((rule, scope, _source(loaded, "permissions", kind, index)))
    if not (project and not trusted):
        for index, directory in enumerate(strings(permissions.get("additionalDirectories"))):
            merged.additional.append(
                (directory, scope, _source(loaded, "permissions", "additionalDirectories", index))
            )
    mode = permissions.get("defaultMode")
    if isinstance(mode, str):
        mode = _MODE_ALIASES.get(mode, mode)
        if not (project and mode in _PROJECT_IGNORED_MODES):
            _scalar(
                merged, "defaultMode", mode, scope, _source(loaded, "permissions", "defaultMode")
            )
    for key in (
        "disableBypassPermissionsMode",
        "disableAutoMode",
        "blockReadsOutsideWorkingDirectories",
    ):
        if key in permissions:
            _scalar(merged, key, permissions[key], scope, _source(loaded, "permissions", key))
    sandbox = mapping(data.get("sandbox"))
    for key in (
        "enabled",
        "autoAllowBashIfSandboxed",
        "allowUnsandboxedCommands",
        "failIfUnavailable",
    ):
        if key in sandbox:
            _scalar(merged, f"sandbox.{key}", sandbox[key], scope, _source(loaded, "sandbox", key))
    for section, key in (
        ("filesystem", "denyRead"),
        ("filesystem", "allowRead"),
        ("network", "allowedDomains"),
        (None, "excludedCommands"),
    ):
        container = mapping(sandbox.get(section)) if section else sandbox
        keypath = ("sandbox", section, key) if section else ("sandbox", key)
        name = ".".join(k for k in keypath if k)
        for index, value in enumerate(strings(container.get(key))):
            source = _source(loaded, *[k for k in keypath if k], index)
            merged.sandbox_lists.setdefault(name, []).append((value, scope, source))
    if mapping(sandbox.get("filesystem")).get("disabled") is True:
        _scalar(
            merged,
            "sandbox.filesystem.disabled",
            True,
            scope,
            _source(loaded, "sandbox", "filesystem"),
        )
    for key in ("enableAllProjectMcpServers", "apiKeyHelper"):
        if key in data:
            _scalar(merged, key, data[key], scope, _source(loaded, key))
    for name in mapping(data.get("env")):
        merged.env_names.append(name)
    for event, entries in mapping(data.get("hooks")).items():
        for i, entry in enumerate(entries if isinstance(entries, list) else []):
            for j, hook in enumerate(mapping(entry).get("hooks") or []):
                hook = mapping(hook)
                if hook.get("type") == "command":
                    program, _ = describe_command(hook.get("command"), None)
                    merged.hooks.append(
                        Hook(
                            AGENT,
                            event,
                            program or "?",
                            scope,
                            _source(loaded, "hooks", event, i, "hooks", j),
                        )
                    )


def _anchor(
    pattern: str, scope: Scope, p: Platform, workspace: Path | None, rule_kind: str
) -> str | None:
    """The absolute pattern for a Read rule's path, per Claude Code's anchoring table."""
    if pattern.startswith("!"):
        return None  # negations carve out of earlier rules; not modelled, reported as unknown
    if pattern.startswith("//"):
        absolute = pattern[1:]
        if p.system is System.WINDOWS:
            match = re.match(r"^/([A-Za-z])/(.*)$", absolute)
            if match:
                return f"{match.group(1).upper()}:\\" + match.group(2).replace("/", "\\")
        return absolute
    if pattern.startswith("~/") or pattern == "~":
        return _join(p.home, pattern[2:])
    if pattern.startswith("/"):
        base = claude_config_dir(p) if scope is Scope.USER else workspace
        return _join(base, pattern[1:]) if base is not None else None
    if workspace is None:
        return None
    relative = pattern.removeprefix("./")
    segments = [s for s in PurePosixPath(relative).parts if s]
    any_depth = len(segments) == 1 or (
        rule_kind in {"deny", "ask"} and len(segments) == 2 and segments[1] == "**"
    )
    if any_depth and not relative.startswith("**"):
        relative = "**/" + relative
    return _join(workspace, relative)


def _join(base: Path, relative: str) -> str:
    joined = str(base)
    for part in relative.split("/"):
        if part:
            joined = str(Path(joined) / part)
    return joined


def _read_rules(
    merged: _Merged, p: Platform, workspace: Path | None, notes: list[str]
) -> list[ReadRule]:
    rules = []
    decisions = (
        ("deny", Gate.DENIED, merged.deny),
        ("ask", Gate.HUMAN, merged.ask),
        ("allow", Gate.NONE, merged.allow),
    )
    for kind, gate, entries in decisions:
        for text, scope, source in entries:
            match = _RULE.match(text)
            if match is None or match.group(1) != "Read":
                continue
            spec = match.group(2)
            if spec is None or spec.strip() in {"", "*", "**"}:
                rules.append(
                    ReadRule(
                        "/**" if p.system is not System.WINDOWS else "C:\\**",
                        gate,
                        _FILE_CHANNELS,
                        source,
                    )
                )
                continue
            absolute = _anchor(spec.strip(), scope, p, workspace, kind)
            if absolute is None:
                notes.append(
                    f"{text} at {source.path}:{source.line} is not modelled"
                    " (a negation, or no workspace)"
                )
                continue
            rules.append(ReadRule(absolute, gate, _FILE_CHANNELS, source))
    return rules


def _bash_rules(merged: _Merged) -> tuple[bool, bool, SourceRef | None]:
    """(shell removed entirely, arbitrary commands allowed without a prompt, where)."""
    removed = any(
        _RULE.match(t) and _RULE.match(t).group(1) == "Bash" and _RULE.match(t).group(2) is None  # type: ignore[union-attr]
        for t, _, _ in merged.deny
    )
    for text, _, source in merged.allow:
        match = _RULE.match(text)
        if match is None or match.group(1) != "Bash":
            continue
        spec = (match.group(2) or "*").strip()
        if _ARBITRARY.match(spec):
            return removed, True, source
    return removed, False, None


def sandbox_available(p: Platform) -> bool | None:
    """Whether Claude Code's sandbox can run here: Seatbelt on macOS, bubblewrap on Linux,
    nothing on native Windows. Only file existence is checked; nothing is run."""
    if p.system is System.WINDOWS:
        return False
    if p.system is System.MACOS:
        return True
    for directory in ("/usr/bin", "/usr/local/bin", "/bin"):
        if stat_entry(p.system_path(f"{directory}/bwrap")).kind is Kind.FILE:
            return True
    return False


def _gates(mode: str, block_outside: bool) -> dict[Channel, tuple[Gate, Gate]]:
    """(inside, outside) gates per channel for a permission mode, before rules apply."""
    if mode == "bypassPermissions":
        file_tool = (Gate.NONE, Gate.NONE)
        recognized = (Gate.NONE, Gate.NONE)
        arbitrary = (Gate.NONE, Gate.NONE)
    elif mode == "auto":
        file_tool = (Gate.NONE, Gate.AUTOMATED)
        recognized = (Gate.NONE, Gate.AUTOMATED)
        arbitrary = (Gate.AUTOMATED, Gate.AUTOMATED)
    elif mode == "dontAsk":
        file_tool = (Gate.NONE, Gate.DENIED)
        recognized = (Gate.NONE, Gate.NONE)
        arbitrary = (Gate.DENIED, Gate.DENIED)
    else:  # default (Manual), acceptEdits, plan
        file_tool = (Gate.NONE, Gate.HUMAN)
        recognized = (Gate.NONE, Gate.NONE)
        arbitrary = (Gate.HUMAN, Gate.HUMAN)
    if block_outside:
        file_tool = (file_tool[0], Gate.DENIED)
        recognized = (
            recognized[0],
            Gate.HUMAN if recognized[1] is not Gate.DENIED else Gate.DENIED,
        )
    return {
        Channel.FILE_TOOL: file_tool,
        Channel.SHELL_RECOGNIZED: recognized,
        Channel.SHELL_ARBITRARY: arbitrary,
    }


def _state(p: Platform, policy: Policy) -> Loaded:
    return load_config(_state_file(p), max(policy.max_file_bytes, MAX_STATE_BYTES))


def _project_state(state: Loaded, workspace: Path | None) -> tuple[dict[str, Any], str | None]:
    if state.document is None or workspace is None:
        return {}, None
    projects = mapping(mapping(state.document.data).get("projects"))
    for key in (str(workspace), str(workspace).replace("\\", "/")):
        if key in projects:
            return mapping(projects[key]), key
    return {}, None


def _server(name: str, spec: Any, scope: Scope, src: SourceRef, approved: bool | None) -> McpServer:
    spec = mapping(spec)
    transport = str(
        spec.get("type")
        or ("stdio" if "command" in spec else "http" if "url" in spec else "unknown")
    )
    program, package = describe_command(spec.get("command"), spec.get("args"))
    url = spec.get("url")
    host = None
    if isinstance(url, str):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
    return McpServer(
        agent=AGENT,
        name=name,
        scope=scope,
        transport=transport,
        program=program,
        package=package,
        host=host,
        env_names=tuple(sorted(mapping(spec.get("env")))),
        header_names=tuple(sorted(mapping(spec.get("headers")))),
        approved=approved,
        source=src,
    )


def _mcp_servers(
    p: Platform,
    workspace: Path | None,
    state: Loaded,
    merged: _Merged,
    project_state: dict[str, Any],
    project_key: str | None,
    policy: Policy,
    layers: list[ConfigLayer],
) -> list[McpServer]:
    servers: list[McpServer] = []
    managed = load_config(claude_managed_dir(p) / "managed-mcp.json", policy.max_file_bytes)
    if managed.exists:
        layers.append(
            ConfigLayer(AGENT, Scope.MANAGED, str(managed.path), True, None, managed.problem)
        )
    for loaded, scope, root in ((managed, Scope.MANAGED, ()),):
        if loaded.document is not None:
            for name, spec in mapping(mapping(loaded.document.data).get("mcpServers")).items():
                servers.append(
                    _server(name, spec, scope, _source(loaded, *root, "mcpServers", name), True)
                )
    if state.document is not None:
        for name, spec in mapping(mapping(state.document.data).get("mcpServers")).items():
            servers.append(
                _server(name, spec, Scope.USER, _source(state, "mcpServers", name), True)
            )
        if project_key is not None:
            for name, spec in mapping(project_state.get("mcpServers")).items():
                servers.append(
                    _server(
                        name,
                        spec,
                        Scope.LOCAL,
                        _source(state, "projects", project_key, "mcpServers", name),
                        True,
                    )
                )
    if workspace is not None:
        project = load_config(workspace / ".mcp.json", policy.max_file_bytes)
        if project.exists:
            layers.append(
                ConfigLayer(AGENT, Scope.PROJECT, str(project.path), True, None, project.problem)
            )
        if project.document is not None:
            approve_all = merged.scalars.get("enableAllProjectMcpServers", (False,))[0] is True
            enabled = set(strings(project_state.get("enabledMcpjsonServers")))
            disabled = set(strings(project_state.get("disabledMcpjsonServers")))
            for name, spec in mapping(mapping(project.document.data).get("mcpServers")).items():
                approved: bool | None
                if name in disabled:
                    approved = False
                elif approve_all or name in enabled:
                    approved = True
                else:
                    approved = None  # asked on first use in an interactive session
                servers.append(
                    _server(
                        name, spec, Scope.PROJECT, _source(project, "mcpServers", name), approved
                    )
                )
    return servers


def inspect_claude_code(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    """Read Claude Code's configuration for ``workspace`` and work out what it may do."""
    state = _state(p, policy)
    project_state, project_key = _project_state(state, workspace)
    trusted = project_state.get("hasTrustDialogAccepted") is True
    layers: list[ConfigLayer] = []
    merged = _Merged()
    notes: list[str] = []
    unknowns: list[str] = []
    for scope, path in _layer_paths(p, workspace):
        loaded = load_config(path, policy.max_file_bytes)
        project = scope in {Scope.PROJECT, Scope.LOCAL}
        if not loaded.exists:
            continue
        layers.append(
            ConfigLayer(AGENT, scope, str(path), True, trusted if project else None, loaded.problem)
        )
        if loaded.document is None:
            unknowns.append(f"{path} could not be read: {loaded.problem}")
            continue
        _merge_layer(merged, loaded, scope, trusted)
    if state.exists:
        layers.append(ConfigLayer(AGENT, Scope.USER, str(state.path), True, None, state.problem))
        if state.document is None:
            unknowns.append(f"{state.path} could not be read: {state.problem}")
    mode_value = merged.scalars.get("defaultMode")
    mode = str(mode_value[0]) if mode_value else "default"
    if mode not in _MODES:
        unknowns.append(f"unknown defaultMode {mode!r}")
        mode = "default"
    block_outside = merged.scalars.get("blockReadsOutsideWorkingDirectories", (False,))[0] is True
    gates = _gates(mode, block_outside)
    removed, arbitrary_allowed, arbitrary_source = _bash_rules(merged)

    sandbox_on = merged.scalars.get("sandbox.enabled", (False,))[0] is True
    available = sandbox_available(p) if sandbox_on else None
    filesystem_off = merged.scalars.get("sandbox.filesystem.disabled", (False,))[0] is True
    auto_allow = merged.scalars.get("sandbox.autoAllowBashIfSandboxed", (True,))[0] is not False
    unsandboxed_retry = (
        merged.scalars.get("sandbox.allowUnsandboxedCommands", (True,))[0] is not False
    )
    read_rules = _read_rules(merged, p, workspace, notes)
    deny_read = [r.pattern for r in read_rules if r.decision is Gate.DENIED]
    for value, scope, _src in merged.sandbox_lists.get("sandbox.filesystem.denyRead", []):
        anchored = _anchor(value, scope, p, workspace, "deny")
        if anchored is not None:
            deny_read.append(anchored)
    escape = [
        f"excludedCommands: {v}"
        for v, _, _ in merged.sandbox_lists.get("sandbox.excludedCommands", [])
    ]
    if sandbox_on and unsandboxed_retry:
        escape.append("allowUnsandboxedCommands (unsandboxed retry after a prompt)")
    sandbox_src = merged.scalars.get("sandbox.enabled", (None, None, None))[2]
    domains = tuple(v for v, _, _ in merged.sandbox_lists.get("sandbox.network.allowedDomains", []))
    effective_sandbox = sandbox_on and available is not False
    sandbox = SandboxPolicy(
        enabled=sandbox_on and not filesystem_off,
        available=available,
        read_deny=tuple(deny_read),
        network=(Network.ALLOWLIST if domains else Network.NONE)
        if effective_sandbox
        else Network.OPEN,
        allowed_domains=domains,
        escape_hatches=tuple(escape),
        source=sandbox_src,
    )
    arbitrary_gate = gates[Channel.SHELL_ARBITRARY]
    if arbitrary_allowed and mode != "bypassPermissions":
        arbitrary_gate = (Gate.NONE, Gate.NONE)
    if effective_sandbox and auto_allow and mode in {"default", "acceptEdits", "plan", "dontAsk"}:
        arbitrary_gate = (Gate.NONE, Gate.NONE)  # sandboxed commands run without a prompt
    channels = [
        ChannelPolicy(
            Channel.FILE_TOOL, *gates[Channel.FILE_TOOL], note="Read, Grep and Glob tools"
        ),
    ]
    if not removed:
        channels.append(
            ChannelPolicy(
                Channel.SHELL_RECOGNIZED,
                *gates[Channel.SHELL_RECOGNIZED],
                sandboxed=effective_sandbox,
                note="read-only Bash commands such as cat and head",
            )
        )
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                *arbitrary_gate,
                sandboxed=effective_sandbox,
                note="Bash commands that open files themselves, such as a Python one-liner",
                source=arbitrary_source,
            )
        )
        if effective_sandbox and unsandboxed_retry:
            channels.append(
                ChannelPolicy(
                    Channel.SHELL_ARBITRARY,
                    Gate.HUMAN,
                    Gate.HUMAN,
                    sandboxed=False,
                    note="a command retried outside the sandbox after a prompt",
                )
            )
    working = [str(workspace)] if workspace is not None else []
    for directory, scope, _src in merged.additional:
        anchored = _anchor(
            directory if directory.startswith(("/", "~")) else "./" + directory,
            scope,
            p,
            workspace,
            "allow",
        )
        if anchored is not None:
            working.append(anchored)
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=tuple(working),
        channels=tuple(channels),
        rules=tuple(read_rules),
        precedence=Precedence.DENY_FIRST,
        sandbox=sandbox,
        unknowns=tuple(unknowns),
    )
    servers = _mcp_servers(p, workspace, state, merged, project_state, project_key, policy, layers)
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("permission mode", mode, mode_value[2] if mode_value else None)
    ]
    for key in (
        "blockReadsOutsideWorkingDirectories",
        "disableBypassPermissionsMode",
        "sandbox.enabled",
        "sandbox.autoAllowBashIfSandboxed",
        "sandbox.allowUnsandboxedCommands",
        "apiKeyHelper",
        "enableAllProjectMcpServers",
    ):
        if key in merged.scalars:
            value, _scope, src = merged.scalars[key]
            shown = value if key != "apiKeyHelper" else (describe_command(value, None)[0] or "set")
            settings.append(
                (key, str(shown).lower() if isinstance(value, bool) else str(shown), src)
            )
    if workspace is not None:
        settings.append(("workspace trusted", "yes" if trusted else "no", None))
    if merged.env_names:
        settings.append(("env (names)", ", ".join(sorted(set(merged.env_names))), None))
    if sandbox_on and available is False:
        notes.append(
            "sandbox.enabled is set, but the sandbox cannot run here; commands run unsandboxed"
        )
    found = bool(layers) or stat_entry(claude_config_dir(p)).kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode=mode,
        mcp_servers=tuple(servers),
        hooks=tuple(merged.hooks),
        settings=tuple(settings),
        notes=tuple(notes),
        facts=(
            "claude.read_inside",
            "claude.readonly_commands",
            "claude.deny_scope",
            "claude.precedence",
            "claude.anchors",
            "claude.modes",
            "claude.sandbox_reads",
            "claude.sandbox_outside",
            "claude.sandbox_auto_allow",
            "claude.trust",
            "claude.mcp_scopes",
        ),
    )
