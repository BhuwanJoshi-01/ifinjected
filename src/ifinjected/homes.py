"""Where each agent keeps its configuration, on this system and for this user.

Everything is resolved from a :class:`Platform`: the operating system, the home
directory, the environment and the root of the file system. Tests build a platform over
a temporary directory, so every agent's files can be created without touching the real
home, and the same code resolves Linux, macOS and Windows locations on any machine.

The locations come from each agent's documentation and source code; the source of every
one is listed in ``docs/what-is-read.md`` (generated from the catalog in a later
change). Overrides the agents honour are honoured here too: ``CLAUDE_CONFIG_DIR``,
``CODEX_HOME``, ``GEMINI_CLI_SYSTEM_DEFAULTS_PATH``, ``GEMINI_CLI_SYSTEM_SETTINGS_PATH``,
``CURSOR_CONFIG_DIR``, ``OPENCODE_CONFIG``, ``OPENCODE_CONFIG_DIR``, ``COPILOT_HOME``
and the XDG variables.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath

from ifinjected.models import AgentId


class System(StrEnum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"

    @classmethod
    def current(cls) -> System:
        if sys.platform == "win32":
            return cls.WINDOWS
        if sys.platform == "darwin":
            return cls.MACOS
        return cls.LINUX


class Scope(StrEnum):
    """Who a configuration layer belongs to, from the most to the least authoritative.

    ``managed``: set by an administrator or a device policy. ``system``: machine-wide
    defaults. ``user``: the user's own settings. ``project``: committed to the
    repository. ``local``: in the repository but not committed (``settings.local.json``).
    """

    MANAGED = "managed"
    SYSTEM = "system"
    USER = "user"
    PROJECT = "project"
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class Platform:
    """The system, home directory and environment paths are resolved against.

    ``root`` is where absolute system paths (``/etc``, ``/Library``, ``C:\\Program
    Files``) are looked up: ``/`` (or the system drive) normally, a temporary directory
    in tests.
    """

    system: System
    home: Path
    env: Mapping[str, str] = field(default_factory=dict)
    root: Path = Path("/")

    @classmethod
    def current(cls) -> Platform:
        system = System.current()
        root = (
            Path(os.environ.get("SYSTEMDRIVE", "C:") + "\\")
            if system is System.WINDOWS
            else Path("/")
        )
        return cls(system=system, home=Path.home(), env=dict(os.environ), root=root)

    def env_value(self, name: str) -> str | None:
        """The variable ``name``, ignoring case on Windows (as Windows does)."""
        value = self.env.get(name)
        if value is None and self.system is System.WINDOWS:
            wanted = name.upper()
            value = next((v for k, v in self.env.items() if k.upper() == wanted), None)
        return value

    def _env_path(self, name: str) -> Path | None:
        """The variable ``name`` as a path; a leading ``~`` means this platform's home."""
        value = (self.env_value(name) or "").strip()
        if not value:
            return None
        if value == "~" or value.startswith(("~/", "~\\")):
            return self.home / value[2:] if len(value) > 1 else self.home
        return Path(value)

    def system_path(self, absolute: str) -> Path:
        """``absolute`` (``/etc/codex`` or ``C:\\ProgramData\\x``) under :attr:`root`."""
        pure = (
            PureWindowsPath(absolute) if self.system is System.WINDOWS else PurePosixPath(absolute)
        )
        parts = pure.parts[1:]  # drop the anchor ("/" or "C:\\")
        return self.root.joinpath(*parts)

    @property
    def xdg_config_home(self) -> Path:
        return self._env_path("XDG_CONFIG_HOME") or self.home / ".config"

    @property
    def xdg_data_home(self) -> Path:
        return self._env_path("XDG_DATA_HOME") or self.home / ".local" / "share"

    @property
    def appdata(self) -> Path:
        """``%APPDATA%`` (Windows roaming application data)."""
        return self._env_path("APPDATA") or self.home / "AppData" / "Roaming"

    @property
    def localappdata(self) -> Path:
        """``%LOCALAPPDATA%`` (Windows local application data)."""
        return self._env_path("LOCALAPPDATA") or self.home / "AppData" / "Local"

    @property
    def xdg_cache_home(self) -> Path:
        return self._env_path("XDG_CACHE_HOME") or self.home / ".cache"

    @property
    def program_data(self) -> Path:
        """``%ProgramData%``, where Windows keeps machine-wide policy files."""
        return self._env_path("ProgramData") or self.system_path("C:\\ProgramData")

    @property
    def program_files(self) -> Path:
        return self._env_path("ProgramFiles") or self.system_path("C:\\Program Files")


@dataclass(frozen=True, slots=True)
class Location:
    """One file (or directory) an agent reads, what it is for and whose it is.

    ``role`` is a stable name the adapters use (``settings``, ``mcp``, ``auth``…).
    """

    agent: AgentId
    role: str
    scope: Scope
    path: Path


def _loc(agent: AgentId, role: str, scope: Scope, path: Path) -> Location:
    return Location(agent, role, scope, path)


# --- Claude Code --------------------------------------------------------------------------
# code.claude.com/docs/en/settings, /managed-settings, /mcp (retrieved 2026-11-05).


def claude_config_dir(p: Platform) -> Path:
    return p._env_path("CLAUDE_CONFIG_DIR") or p.home / ".claude"


def claude_state_file(p: Platform) -> Path:
    """``~/.claude.json``: user and per-project MCP servers, trust, approvals. Moves into
    ``CLAUDE_CONFIG_DIR`` when that is set."""
    override = p._env_path("CLAUDE_CONFIG_DIR")
    return override / ".claude.json" if override else p.home / ".claude.json"


def claude_managed_dir(p: Platform) -> Path:
    if p.system is System.MACOS:
        return p.system_path("/Library/Application Support/ClaudeCode")
    if p.system is System.WINDOWS:
        return p.program_files / "ClaudeCode"
    return p.system_path("/etc/claude-code")


def _claude(p: Platform, workspace: Path | None) -> list[Location]:
    a, user, managed = AgentId.CLAUDE_CODE, claude_config_dir(p), claude_managed_dir(p)
    found = [
        _loc(a, "managed_settings", Scope.MANAGED, managed / "managed-settings.json"),
        _loc(a, "managed_settings_dir", Scope.MANAGED, managed / "managed-settings.d"),
        _loc(a, "managed_mcp", Scope.MANAGED, managed / "managed-mcp.json"),
        _loc(a, "settings", Scope.USER, user / "settings.json"),
        _loc(a, "state", Scope.USER, claude_state_file(p)),
        _loc(a, "auth", Scope.USER, user / ".credentials.json"),
        _loc(a, "transcripts", Scope.USER, user / "projects"),
        _loc(a, "history", Scope.USER, user / "history.jsonl"),
    ]
    if workspace is not None:
        found += [
            _loc(a, "settings", Scope.PROJECT, workspace / ".claude" / "settings.json"),
            _loc(a, "settings", Scope.LOCAL, workspace / ".claude" / "settings.local.json"),
            _loc(a, "mcp", Scope.PROJECT, workspace / ".mcp.json"),
        ]
    return found


# --- Codex --------------------------------------------------------------------------------
# learn.chatgpt.com/docs/config-file/config-reference, /enterprise/managed-configuration
# (retrieved 2026-11-05).


def codex_home(p: Platform) -> Path:
    return p._env_path("CODEX_HOME") or p.home / ".codex"


def _codex(p: Platform, workspace: Path | None) -> list[Location]:
    a, user = AgentId.CODEX, codex_home(p)
    if p.system is System.WINDOWS:
        requirements = p.program_data / "OpenAI" / "Codex" / "requirements.toml"
        managed = user / "managed_config.toml"
        system_config = None  # no documented machine-wide config.toml on Windows
    else:
        requirements = p.system_path("/etc/codex/requirements.toml")
        managed = p.system_path("/etc/codex/managed_config.toml")
        system_config = p.system_path("/etc/codex/config.toml")
    found = [
        _loc(a, "requirements", Scope.MANAGED, requirements),
        _loc(a, "managed_config", Scope.MANAGED, managed),
    ]
    if system_config is not None:
        found.append(_loc(a, "config", Scope.SYSTEM, system_config))
    found += [
        _loc(a, "config", Scope.USER, user / "config.toml"),
        _loc(a, "profiles", Scope.USER, user),
        _loc(a, "auth", Scope.USER, user / "auth.json"),
        _loc(a, "history", Scope.USER, user / "history.jsonl"),
        _loc(a, "transcripts", Scope.USER, user / "sessions"),
    ]
    if workspace is not None:
        found.append(_loc(a, "config", Scope.PROJECT, workspace / ".codex" / "config.toml"))
    return found


# --- Gemini CLI ---------------------------------------------------------------------------
# github.com/google-gemini/gemini-cli docs/reference/configuration.md (retrieved 2026-11-05).


def gemini_system_dir(p: Platform) -> Path:
    if p.system is System.MACOS:
        return p.system_path("/Library/Application Support/GeminiCli")
    if p.system is System.WINDOWS:
        return p.program_data / "gemini-cli"
    return p.system_path("/etc/gemini-cli")


def _gemini(p: Platform, workspace: Path | None) -> list[Location]:
    a, user, system = AgentId.GEMINI_CLI, p.home / ".gemini", gemini_system_dir(p)
    defaults = p._env_path("GEMINI_CLI_SYSTEM_DEFAULTS_PATH") or system / "system-defaults.json"
    override = p._env_path("GEMINI_CLI_SYSTEM_SETTINGS_PATH") or system / "settings.json"
    found = [
        _loc(a, "system_override", Scope.MANAGED, override),
        _loc(a, "policies", Scope.MANAGED, system / "policies"),
        _loc(a, "system_defaults", Scope.SYSTEM, defaults),
        _loc(a, "settings", Scope.USER, user / "settings.json"),
        _loc(a, "policies", Scope.USER, user / "policies"),
        _loc(a, "trusted_folders", Scope.USER, user / "trustedFolders.json"),
        _loc(a, "auth", Scope.USER, user / "oauth_creds.json"),
        _loc(a, "accounts", Scope.USER, user / "google_accounts.json"),
    ]
    if workspace is not None:
        found.append(_loc(a, "settings", Scope.PROJECT, workspace / ".gemini" / "settings.json"))
    return found


# --- Cursor -------------------------------------------------------------------------------
# cursor.com/docs/cli/reference/configuration, /reference/sandbox, /context/mcp
# (retrieved 2026-11-05).


def cursor_dir(p: Platform) -> Path:
    return p._env_path("CURSOR_CONFIG_DIR") or p.home / ".cursor"


def _cursor(p: Platform, workspace: Path | None) -> list[Location]:
    a, user = AgentId.CURSOR, cursor_dir(p)
    found = [
        _loc(a, "cli_config", Scope.USER, user / "cli-config.json"),
        _loc(a, "cli_config", Scope.USER, p.xdg_config_home / "cursor" / "cli-config.json"),
        _loc(a, "sandbox", Scope.USER, user / "sandbox.json"),
        _loc(a, "mcp", Scope.USER, user / "mcp.json"),
    ]
    if workspace is not None:
        found += [
            _loc(a, "cli_config", Scope.PROJECT, workspace / ".cursor" / "cli.json"),
            _loc(a, "sandbox", Scope.PROJECT, workspace / ".cursor" / "sandbox.json"),
            _loc(a, "mcp", Scope.PROJECT, workspace / ".cursor" / "mcp.json"),
        ]
    return found


# --- opencode -----------------------------------------------------------------------------
# opencode.ai/docs/config, /permissions (retrieved 2026-11-05).


def opencode_config_dir(p: Platform) -> Path:
    return p._env_path("OPENCODE_CONFIG_DIR") or p.xdg_config_home / "opencode"


def opencode_managed_dir(p: Platform) -> Path:
    if p.system is System.MACOS:
        return p.system_path("/Library/Application Support/opencode")
    if p.system is System.WINDOWS:
        return p.program_data / "opencode"
    return p.system_path("/etc/opencode")


def _opencode(p: Platform, workspace: Path | None) -> list[Location]:
    a, user, managed = AgentId.OPENCODE, opencode_config_dir(p), opencode_managed_dir(p)
    found = [
        _loc(a, "config", Scope.MANAGED, managed / "opencode.json"),
        _loc(a, "config", Scope.MANAGED, managed / "opencode.jsonc"),
        _loc(a, "config", Scope.USER, user / "opencode.json"),
        _loc(a, "config", Scope.USER, user / "opencode.jsonc"),
        _loc(a, "auth", Scope.USER, p.xdg_data_home / "opencode" / "auth.json"),
    ]
    custom = p._env_path("OPENCODE_CONFIG")
    if custom is not None:
        found.append(_loc(a, "config", Scope.USER, custom))
    if workspace is not None:
        found += [
            _loc(a, "config", Scope.PROJECT, workspace / "opencode.json"),
            _loc(a, "config", Scope.PROJECT, workspace / "opencode.jsonc"),
            _loc(a, "config_dir", Scope.PROJECT, workspace / ".opencode"),
        ]
    return found


# --- Copilot CLI --------------------------------------------------------------------------
# docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference
# (retrieved 2026-11-05).


def copilot_home(p: Platform) -> Path:
    return p._env_path("COPILOT_HOME") or p.home / ".copilot"


def _copilot(p: Platform, workspace: Path | None) -> list[Location]:
    a, user = AgentId.COPILOT_CLI, copilot_home(p)
    found = [
        _loc(a, "settings", Scope.USER, user / "settings.json"),
        _loc(a, "state", Scope.USER, user / "config.json"),
        _loc(a, "permissions", Scope.USER, user / "permissions-config.json"),
        _loc(a, "mcp", Scope.USER, user / "mcp-config.json"),
        _loc(a, "auth", Scope.USER, user / "providers.json"),
        _loc(a, "transcripts", Scope.USER, user / "session-state"),
    ]
    if workspace is not None:
        copilot = workspace / ".github" / "copilot"
        found += [
            _loc(a, "settings", Scope.PROJECT, copilot / "settings.json"),
            _loc(a, "settings", Scope.LOCAL, copilot / "settings.local.json"),
            _loc(a, "mcp", Scope.PROJECT, workspace / ".github" / "mcp.json"),
            # Copilot CLI also loads Claude Code's project files.
            _loc(a, "mcp", Scope.PROJECT, workspace / ".mcp.json"),
            _loc(a, "claude_settings", Scope.PROJECT, workspace / ".claude" / "settings.json"),
        ]
    return found


_RESOLVERS = {
    AgentId.CLAUDE_CODE: _claude,
    AgentId.CODEX: _codex,
    AgentId.GEMINI_CLI: _gemini,
    AgentId.CURSOR: _cursor,
    AgentId.OPENCODE: _opencode,
    AgentId.COPILOT_CLI: _copilot,
}


def agent_locations(
    agent: AgentId, platform: Platform, workspace: Path | None = None
) -> tuple[Location, ...]:
    """Every file and directory ``agent`` reads on ``platform``, most authoritative
    scope first; project and local ones only when a ``workspace`` is given."""
    return tuple(_RESOLVERS[agent](platform, workspace))
