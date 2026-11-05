"""Where every agent's files are, per system, with the agents' own overrides."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.homes import (
    Platform,
    Scope,
    System,
    agent_locations,
    claude_config_dir,
    claude_managed_dir,
    claude_state_file,
    codex_home,
    copilot_home,
    cursor_dir,
    gemini_system_dir,
    opencode_config_dir,
)
from ifinjected.models import AgentId
from tests.homes import FakeMachine


def _platform(tmp_path: Path, system: System, **env: str) -> Platform:
    return FakeMachine(tmp_path, system, env=dict(env)).platform()


def _paths(
    platform: Platform, agent: AgentId, role: str, workspace: Path | None = None
) -> list[Path]:
    return [loc.path for loc in agent_locations(agent, platform, workspace) if loc.role == role]


# --- the platform -------------------------------------------------------------------------


def test_system_paths_land_under_the_root(tmp_path: Path) -> None:
    linux = _platform(tmp_path, System.LINUX)
    assert (
        linux.system_path("/etc/codex/config.toml") == linux.root / "etc" / "codex" / "config.toml"
    )
    windows = _platform(tmp_path, System.WINDOWS)
    assert windows.system_path("C:\\ProgramData\\x") == windows.root / "ProgramData" / "x"


def test_xdg_variables_move_config_and_data(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX, XDG_CONFIG_HOME="/cfg", XDG_DATA_HOME="/data")
    assert (p.xdg_config_home, p.xdg_data_home) == (Path("/cfg"), Path("/data"))
    plain = _platform(tmp_path, System.LINUX)
    assert plain.xdg_config_home == plain.home / ".config"
    assert plain.xdg_data_home == plain.home / ".local" / "share"


def test_windows_variables_are_found_whatever_their_case(tmp_path: Path) -> None:
    p = Platform(System.WINDOWS, tmp_path, env={"PROGRAMDATA": "D:\\PD"}, root=tmp_path)
    assert p.env_value("ProgramData") == "D:\\PD"
    assert p.program_data == Path("D:\\PD")
    linux = Platform(System.LINUX, tmp_path, env={"XDG_CONFIG_HOME": "/x"}, root=tmp_path)
    assert linux.env_value("xdg_config_home") is None


def test_a_tilde_in_an_override_means_this_platforms_home(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX, CODEX_HOME="~/agents/codex")
    assert codex_home(p) == p.home / "agents" / "codex"


def test_an_empty_override_is_ignored(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX, CODEX_HOME="  ")
    assert codex_home(p) == p.home / ".codex"


def test_the_current_platform_is_this_machine() -> None:
    p = Platform.current()
    assert p.home == Path.home()
    assert p.system is System.current()


# --- Claude Code --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "managed"),
    [
        (System.LINUX, ("etc", "claude-code")),
        (System.MACOS, ("Library", "Application Support", "ClaudeCode")),
        (System.WINDOWS, ("Program Files", "ClaudeCode")),
    ],
)
def test_claude_managed_settings_per_system(
    tmp_path: Path, system: System, managed: tuple[str, ...]
) -> None:
    p = _platform(tmp_path, system)
    assert claude_managed_dir(p) == p.root.joinpath(*managed)
    assert _paths(p, AgentId.CLAUDE_CODE, "managed_settings") == [
        p.root.joinpath(*managed, "managed-settings.json")
    ]


def test_claude_user_files_and_their_override(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX)
    assert claude_config_dir(p) == p.home / ".claude"
    assert claude_state_file(p) == p.home / ".claude.json"
    moved = _platform(tmp_path, System.LINUX, CLAUDE_CONFIG_DIR="/opt/claude")
    assert claude_config_dir(moved) == Path("/opt/claude")
    assert claude_state_file(moved) == Path("/opt/claude/.claude.json")


def test_claude_project_layers_need_a_workspace(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX)
    ws = tmp_path / "repo"
    without = {(loc.scope, loc.role) for loc in agent_locations(AgentId.CLAUDE_CODE, p)}
    assert (Scope.PROJECT, "settings") not in without
    with_ws = [
        (loc.scope, loc.path)
        for loc in agent_locations(AgentId.CLAUDE_CODE, p, ws)
        if loc.role in {"settings", "mcp"}
    ]
    assert (Scope.PROJECT, ws / ".claude" / "settings.json") in with_ws
    assert (Scope.LOCAL, ws / ".claude" / "settings.local.json") in with_ws
    assert (Scope.PROJECT, ws / ".mcp.json") in with_ws


# --- the other agents ---------------------------------------------------------------------


def test_codex_layers_on_linux_and_windows(tmp_path: Path) -> None:
    linux = _platform(tmp_path, System.LINUX)
    assert _paths(linux, AgentId.CODEX, "requirements") == [
        linux.root / "etc/codex/requirements.toml"
    ]
    assert _paths(linux, AgentId.CODEX, "config") == [
        linux.root / "etc/codex/config.toml",
        linux.home / ".codex/config.toml",
    ]
    windows = _platform(tmp_path, System.WINDOWS)
    assert _paths(windows, AgentId.CODEX, "requirements") == [
        windows.root / "ProgramData/OpenAI/Codex/requirements.toml"
    ]
    assert _paths(windows, AgentId.CODEX, "managed_config") == [
        windows.home / ".codex/managed_config.toml"
    ]
    assert _paths(windows, AgentId.CODEX, "config") == [windows.home / ".codex/config.toml"]


def test_codex_home_moves_every_user_file(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX, CODEX_HOME="/srv/codex")
    user = {loc.path for loc in agent_locations(AgentId.CODEX, p) if loc.scope is Scope.USER}
    assert all(path.is_relative_to("/srv/codex") for path in user)


@pytest.mark.parametrize(
    ("system", "parts"),
    [
        (System.LINUX, ("etc", "gemini-cli")),
        (System.MACOS, ("Library", "Application Support", "GeminiCli")),
        (System.WINDOWS, ("ProgramData", "gemini-cli")),
    ],
)
def test_gemini_system_settings_per_system(
    tmp_path: Path, system: System, parts: tuple[str, ...]
) -> None:
    p = _platform(tmp_path, system)
    assert gemini_system_dir(p) == p.root.joinpath(*parts)


def test_gemini_system_paths_can_be_overridden(tmp_path: Path) -> None:
    p = _platform(
        tmp_path,
        System.LINUX,
        GEMINI_CLI_SYSTEM_DEFAULTS_PATH="/x/defaults.json",
        GEMINI_CLI_SYSTEM_SETTINGS_PATH="/x/override.json",
    )
    assert _paths(p, AgentId.GEMINI_CLI, "system_defaults") == [Path("/x/defaults.json")]
    assert _paths(p, AgentId.GEMINI_CLI, "system_override") == [Path("/x/override.json")]


def test_cursor_reads_two_cli_config_locations_and_its_override(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX)
    assert _paths(p, AgentId.CURSOR, "cli_config") == [
        p.home / ".cursor/cli-config.json",
        p.home / ".config/cursor/cli-config.json",
    ]
    moved = _platform(tmp_path, System.LINUX, CURSOR_CONFIG_DIR="/c")
    assert cursor_dir(moved) == Path("/c")


def test_opencode_config_auth_and_custom_file(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX, OPENCODE_CONFIG="/x/oc.json")
    assert opencode_config_dir(p) == p.home / ".config/opencode"
    assert _paths(p, AgentId.OPENCODE, "auth") == [p.home / ".local/share/opencode/auth.json"]
    assert Path("/x/oc.json") in _paths(p, AgentId.OPENCODE, "config")


def test_copilot_loads_claude_codes_project_files_too(tmp_path: Path) -> None:
    p = _platform(tmp_path, System.LINUX)
    ws = tmp_path / "repo"
    assert copilot_home(p) == p.home / ".copilot"
    assert ws / ".mcp.json" in _paths(p, AgentId.COPILOT_CLI, "mcp", ws)
    assert _paths(p, AgentId.COPILOT_CLI, "claude_settings", ws) == [ws / ".claude/settings.json"]
    assert _paths(p, AgentId.COPILOT_CLI, "auth") == [p.home / ".copilot/providers.json"]


@pytest.mark.parametrize("agent", list(AgentId))
@pytest.mark.parametrize("system", list(System))
def test_every_agent_resolves_on_every_system_most_authoritative_first(
    tmp_path: Path, agent: AgentId, system: System
) -> None:
    p = _platform(tmp_path, system)
    locations = agent_locations(agent, p, tmp_path / "repo")
    assert locations
    order = list(Scope)
    ranks = [order.index(loc.scope) for loc in locations if loc.role not in {"auth"}]
    # Within the configuration roles, more authoritative scopes come first.
    assert all(loc.agent is agent for loc in locations)
    assert ranks[0] <= ranks[-1]


# --- the fake machine ---------------------------------------------------------------------


def test_the_fake_machine_writes_where_the_resolvers_look(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    p = machine.platform()
    machine.write(".claude/settings.json", {"permissions": {}})
    assert (claude_config_dir(p) / "settings.json").is_file()
    machine.add_credentials()
    assert (p.home / ".ssh" / "id_ed25519").is_file()
    assert (machine.workspace / ".env").is_file()
    assert p.home.is_relative_to(tmp_path)  # never the real home
