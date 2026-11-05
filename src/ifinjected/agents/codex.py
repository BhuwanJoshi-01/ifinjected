"""Codex: configuration layers, sandbox modes and permission profiles, MCP servers.

Codex runs every command it spawns in an OS sandbox (Seatbelt, bubblewrap, the Windows
sandbox) unless the mode is ``danger-full-access``. Inside the sandbox, ``read-only`` and
``workspace-write`` both start from read access to the filesystem root, so a sandboxed
``cat ~/.ssh/id_ed25519`` works without any approval; only a ``[permissions.<name>]``
profile with ``"deny"`` entries takes paths away. Going beyond the sandbox needs
approval under ``on-request`` and is impossible under ``never``.

Layers, most authoritative first: the trusted project's ``.codex/config.toml``, the
selected profile, ``managed_config.toml``, the user's ``config.toml`` and the system's
``/etc/codex/config.toml``. ``requirements.toml`` restricts what may be chosen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
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
from ifinjected.agents.claude_code import sandbox_available as _bwrap_available
from ifinjected.files import Kind, stat_entry
from ifinjected.homes import Platform, Scope, System, agent_locations, codex_home
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

AGENT = AgentId.CODEX
_MODES = ("read-only", "workspace-write", "danger-full-access")
_BUILTIN_PROFILES = {":read-only": "read-only", ":workspace": "workspace-write",
                     ":danger-full-access": "danger-full-access"}  # fmt: skip


@dataclass(slots=True)
class _Merged:
    scalars: dict[str, tuple[Any, SourceRef]] = field(default_factory=dict)
    tables: dict[str, list[tuple[dict[str, Any], Loaded, tuple[str, ...], Scope]]] = field(
        default_factory=dict
    )


def _src(loaded: Loaded, *path: str | int) -> SourceRef:
    line = loaded.document.line(*path) if loaded.document else None
    return SourceRef(str(loaded.path), line, key_name(tuple(path)) if path else None)


def _get(data: dict[str, Any], dotted: str) -> Any:
    value: Any = data
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


_SCALARS = (
    "sandbox_mode", "approval_policy", "default_permissions", "web_search",
    "sandbox_workspace_write.network_access", "shell_environment_policy.inherit",
    "shell_environment_policy.ignore_default_excludes", "profile", "notify",
)  # fmt: skip


def _absorb(merged: _Merged, loaded: Loaded, scope: Scope, root: tuple[str, ...] = ()) -> None:
    if loaded.document is None:
        return
    data = mapping(loaded.document.data)
    for part in root:
        data = mapping(data.get(part))
    for key in _SCALARS:
        value = _get(data, key)
        if value is not None and key not in merged.scalars:
            merged.scalars[key] = (value, _src(loaded, *root, *key.split(".")))
    for table in ("mcp_servers", "permissions"):
        value = mapping(data.get(table))
        if value:
            merged.tables.setdefault(table, []).append((value, loaded, (*root, table), scope))


def _trusted(user: Loaded, workspace: Path | None) -> bool:
    if user.document is None or workspace is None:
        return False
    projects = mapping(mapping(user.document.data).get("projects"))
    for key in (str(workspace), str(workspace).replace("\\", "/")):
        if mapping(projects.get(key)).get("trust_level") == "trusted":
            return True
    return False


def _expand(path: str, p: Platform, workspace: Path | None) -> str | None:
    if path.startswith("~/") or path == "~":
        return str(p.home / path[2:]) if len(path) > 1 else str(p.home)
    if path in {":workspace_roots", ":cwd"} and workspace is not None:
        return str(workspace)
    if path.startswith(":"):
        return None  # :root, :minimal, :tmpdir: special tokens, not denials we can model
    if path.startswith("**"):
        return "**" if path == "**" else None
    return path


def _profile_denials(
    merged: _Merged, name: str, p: Platform, workspace: Path | None, notes: list[str]
) -> tuple[list[str], bool | None, SourceRef | None]:
    """(denied read patterns, network enabled, where) of permissions profile ``name``."""
    for table, loaded, root, _scope in merged.tables.get("permissions", []):
        profile = mapping(table.get(name))
        if not profile:
            continue
        denied = []
        for path, decision in mapping(profile.get("filesystem")).items():
            if decision == "deny":
                expanded = _expand(path, p, workspace)
                if expanded is None:
                    notes.append(f"permissions.{name}.filesystem {path!r} is not modelled")
                else:
                    denied.append(expanded)
            elif isinstance(decision, dict):
                base = _expand(path, p, workspace)
                for sub, sub_decision in decision.items():
                    if sub_decision == "deny" and base is not None:
                        denied.append(str(Path(base) / sub))
        network = mapping(profile.get("network")).get("enabled")
        return denied, network if isinstance(network, bool) else None, _src(loaded, *root, name)
    return [], None, None


def _servers(merged: _Merged) -> list[tuple[McpServer, Any]]:
    found: list[tuple[McpServer, Any]] = []
    seen: set[str] = set()
    for table, loaded, root, scope in merged.tables.get("mcp_servers", []):
        for name, spec in table.items():
            if name in seen:
                continue
            seen.add(name)
            spec = mapping(spec)
            program, package = describe_command(spec.get("command"), spec.get("args"))
            url = spec.get("url")
            host = urlsplit(url).hostname if isinstance(url, str) else None
            server = McpServer(
                agent=AGENT,
                name=name,
                scope=scope,
                transport="stdio" if "command" in spec else "http" if url else "unknown",
                program=program,
                package=package,
                host=host,
                env_names=tuple(sorted(mapping(spec.get("env")))),
                header_names=("bearer token",) if spec.get("bearer_token_env_var") else (),
                approved=spec.get("enabled") is not False,
                source=_src(loaded, *root, name),
            )
            found.append((server, spec.get("default_tools_approval_mode")))
    return found


def _sandbox_available(p: Platform) -> bool | None:
    if p.system is System.MACOS or p.system is System.WINDOWS:
        return True
    return True if _bwrap_available(p) else None  # bubblewrap, or Landlock on some kernels


def inspect_codex(p: Platform, policy: Policy, workspace: Path | None) -> AgentReport:
    """Read Codex's configuration for ``workspace`` and work out what it may do."""
    locations = agent_locations(AGENT, p, workspace)
    paths = {(loc.role, loc.scope): loc.path for loc in locations}
    layers: list[ConfigLayer] = []
    unknowns: list[str] = []
    notes: list[str] = []

    def load(path: Path | None, scope: Scope, trusted: bool | None = None) -> Loaded | None:
        if path is None:
            return None
        loaded = load_config(path, policy.max_file_bytes, kind="toml")
        if loaded.exists:
            layers.append(ConfigLayer(AGENT, scope, str(path), True, trusted, loaded.problem))
            if loaded.problem:
                unknowns.append(f"{path} could not be read: {loaded.problem}")
        return loaded

    user = load(paths.get(("config", Scope.USER)), Scope.USER) or Loaded(Path(), None, False)
    trusted = _trusted(user, workspace)
    project = (
        load(paths.get(("config", Scope.PROJECT)), Scope.PROJECT, trusted) if workspace else None
    )
    managed = load(paths.get(("managed_config", Scope.MANAGED)), Scope.MANAGED)
    system = load(paths.get(("config", Scope.SYSTEM)), Scope.SYSTEM)
    requirements = load(paths.get(("requirements", Scope.MANAGED)), Scope.MANAGED)

    merged = _Merged()
    if project is not None and trusted:
        _absorb(merged, project, Scope.PROJECT)
    profile_name = None
    for source in (project if trusted else None, user):
        if source is not None and source.document is not None:
            value = mapping(source.document.data).get("profile")
            if isinstance(value, str):
                profile_name = value
                break
    if profile_name is not None and user.document is not None:
        if mapping(mapping(user.document.data).get("profiles")).get(profile_name):
            _absorb(merged, user, Scope.USER, ("profiles", profile_name))
        profile_file = load(codex_home(p) / f"{profile_name}.config.toml", Scope.USER)
        if profile_file is not None:
            _absorb(merged, profile_file, Scope.USER)
    for source, scope in ((managed, Scope.MANAGED), (user, Scope.USER), (system, Scope.SYSTEM)):
        if source is not None:
            _absorb(merged, source, scope)

    mode_value = merged.scalars.get("sandbox_mode")
    profile_value = merged.scalars.get("default_permissions")
    denied: list[str] = []
    network: bool | None = None
    profile_source: SourceRef | None = None
    if mode_value is not None:
        mode = str(mode_value[0])
    elif profile_value is not None:
        name = str(profile_value[0])
        mode = _BUILTIN_PROFILES.get(name, "workspace-write")
        if name not in _BUILTIN_PROFILES:
            denied, network, profile_source = _profile_denials(merged, name, p, workspace, notes)
    else:
        mode = "workspace-write" if trusted else "read-only"
    if mode not in _MODES:
        unknowns.append(f"unknown sandbox_mode {mode!r}")
        mode = "workspace-write"
    approval_value = merged.scalars.get("approval_policy")
    approval = (
        str(approval_value[0])
        if approval_value and isinstance(approval_value[0], str)
        else "on-request"
    )
    if approval_value and not isinstance(approval_value[0], str):
        approval = "granular"
        unknowns.append("approval_policy uses granular rules; treated like on-request")
    if network is None:
        network_value = merged.scalars.get("sandbox_workspace_write.network_access")
        network = network_value[0] is True if network_value else False
    full_access = mode == "danger-full-access"
    available = None if full_access else _sandbox_available(p)
    sandbox = SandboxPolicy(
        enabled=not full_access,
        available=available,
        read_deny=tuple(denied),
        network=Network.OPEN if network or full_access else Network.NONE,
        unlisted_hosts=Gate.DENIED,
        source=profile_source or (mode_value[1] if mode_value else None),
    )
    escalate = Gate.HUMAN if approval in {"on-request", "granular"} else Gate.DENIED
    channels = []
    if full_access:
        gate = Gate.NONE  # full access: commands run unsandboxed and unasked
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                gate,
                gate,
                sandboxed=False,
                note="every command, with full access",
            )
        )
    else:
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                Gate.NONE,
                Gate.NONE,
                sandboxed=True,
                note="commands inside the sandbox, which reads the whole disk",
            )
        )
        channels.append(
            ChannelPolicy(
                Channel.SHELL_ARBITRARY,
                escalate,
                escalate,
                sandboxed=False,
                note="a command run outside the sandbox after approval",
            )
        )
    inherit = merged.scalars.get("shell_environment_policy.inherit")
    keep = merged.scalars.get("shell_environment_policy.ignore_default_excludes")
    env_secrets = not (
        (inherit is not None and inherit[0] == "none") or (keep is not None and keep[0] is False)
    )
    servers_with_modes = _servers(merged)
    servers = [s for s, _ in servers_with_modes]
    mcp_gates = []
    for server, approval_mode in servers_with_modes:
        if server.approved is False:
            continue
        if approval == "never" or approval_mode == "auto":
            mcp_gates.append((server.name, Gate.NONE))
        else:
            mcp_gates.append((server.name, Gate.HUMAN))
    web = merged.scalars.get("web_search")
    web_gate = None if web is not None and web[0] in {"disabled", False} else Gate.NONE
    working = [str(workspace)] if workspace is not None else []
    effective = EffectivePolicy(
        agent=AGENT,
        working_dirs=tuple(working),
        channels=tuple(channels),
        sandbox=sandbox,
        unknowns=tuple(unknowns),
        web_search=web_gate,
        mcp_gates=tuple(mcp_gates),
        inherits_secret_env=env_secrets,
    )
    hooks = []
    notify = merged.scalars.get("notify")
    if notify is not None:
        program, _ = describe_command(notify[0], None)
        if program:
            hooks.append(Hook(AGENT, "notify", program, Scope.USER, notify[1]))
    settings: list[tuple[str, str, SourceRef | None]] = [
        ("sandbox mode", mode, mode_value[1] if mode_value else None),
        ("approval policy", approval, approval_value[1] if approval_value else None),
        ("network in the sandbox", "on" if network or full_access else "off", None),
        (
            "secret-named variables inherited",
            "yes" if env_secrets else "no",
            keep[1] if keep else None,
        ),
    ]
    if workspace is not None:
        settings.append(("workspace trusted", "yes" if trusted else "no", None))
    if profile_name:
        settings.append(("profile", profile_name, None))
    if requirements is not None and requirements.document is not None:
        allowed = strings(mapping(requirements.document.data).get("allowed_sandbox_modes"))
        if allowed:
            settings.append(
                (
                    "allowed sandbox modes (managed)",
                    ", ".join(allowed),
                    _src(requirements, "allowed_sandbox_modes"),
                )
            )
    if available is None and not full_access and p.system is System.LINUX:
        notes.append("bubblewrap was not found; Codex may fall back to Landlock or run unsandboxed")
    found = bool(layers) or stat_entry(codex_home(p)).kind is Kind.DIRECTORY
    return AgentReport(
        agent=AGENT,
        found=found,
        layers=tuple(layers),
        policy=effective,
        mode=f"{mode} + {approval}",
        mcp_servers=tuple(servers),
        hooks=tuple(hooks),
        settings=tuple(settings),
        notes=tuple(notes),
        facts=(
            "codex.modes",
            "codex.approvals",
            "codex.reads",
            "codex.network",
            "codex.env",
            "codex.deny",
            "codex.trust",
            "codex.platforms",
        ),
    )
