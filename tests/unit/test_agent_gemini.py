"""Gemini CLI: layers, trust, tool lists, sandbox kinds and MCP servers (IFJ-024)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ifinjected.agents.gemini import inspect_gemini
from ifinjected.files import Level, recording
from ifinjected.homes import Scope, System, gemini_system_dir
from ifinjected.inventory.catalog import load_catalog
from ifinjected.models import Policy, Reach
from ifinjected.policy.model import Channel, Gate
from ifinjected.policy.reach import reach_of
from tests import canaries
from tests.homes import FakeMachine


def _machine(tmp_path: Path, system: System = System.LINUX, **env: str) -> FakeMachine:
    machine = FakeMachine(tmp_path, system, env=dict(env))
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return machine


def _inspect(machine: FakeMachine) -> Any:
    return inspect_gemini(machine.platform(), Policy(), machine.workspace)


def _channel(report: Any, channel: Channel) -> Any:
    return next((c for c in report.policy.channels if c.channel is channel), None)


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_defaults_files_stay_in_the_workspace_and_the_shell_asks(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".gemini/settings.json", {"security": {"auth": {"selectedType": "oauth-personal"}}}
    )
    report = _inspect(machine)
    files = _channel(report, Channel.FILE_TOOL)
    shell = _channel(report, Channel.SHELL_ARBITRARY)
    assert (files.gate_inside, files.gate_outside) == (Gate.NONE, Gate.DENIED)
    assert (shell.gate_outside, shell.sandboxed) == (Gate.HUMAN, False)
    assert report.policy.web_fetch is Gate.HUMAN
    key = str(machine.home / ".ssh" / "id_ed25519")
    assert reach_of(report.policy, key).reach is Reach.AFTER_APPROVAL  # a shell command, approved
    env = str(machine.workspace / ".env")
    assert reach_of(report.policy, env).reach is Reach.NO_APPROVAL  # read_file in the workspace


@pytest.mark.parametrize(
    ("allowed", "gate"),
    [
        (["run_shell_command(git)"], Gate.HUMAN),
        (["run_shell_command(python3)"], Gate.NONE),
        (["run_shell_command"], Gate.NONE),
    ],
)
def test_allowed_shell_commands(tmp_path: Path, allowed: list[str], gate: Gate) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {"tools": {"allowed": allowed}})
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is gate


@pytest.mark.parametrize(
    "settings",
    [{"tools": {"exclude": ["run_shell_command"]}}, {"tools": {"core": ["read_file", "glob"]}}],
)
def test_the_shell_can_be_removed(tmp_path: Path, settings: dict[str, Any]) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", settings)
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY) is None


def test_a_policy_file_can_allow_or_deny_the_shell(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {})
    machine.write(
        ".gemini/policies/dev.toml",
        '[[rule]]\ntoolName = "run_shell_command"\ncommandPrefix = "node"\ndecision = "allow"\n',
    )
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is Gate.NONE
    machine.write(
        ".gemini/policies/lock.toml",
        '[[rule]]\ntoolName = "run_shell_command"\ndecision = "deny"\n',
    )
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY) is None


def test_the_project_layer_merges_and_the_override_wins(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {"general": {"defaultApprovalMode": "default"}})
    machine.write_workspace(
        ".gemini/settings.json", {"general": {"defaultApprovalMode": "auto_edit"}}
    )
    assert _inspect(machine).mode == "auto_edit"
    machine.write_at(
        gemini_system_dir(machine.platform()) / "settings.json",
        {"general": {"defaultApprovalMode": "plan"}},
    )
    assert _inspect(machine).mode == "plan"


def test_an_untrusted_folder_ignores_project_settings(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {"security": {"folderTrust": {"enabled": True}}})
    machine.write_workspace(
        ".gemini/settings.json",
        {"tools": {"allowed": ["run_shell_command"]}, "mcpServers": {"repo": {"command": "x"}}},
    )
    report = _inspect(machine)
    assert _channel(report, Channel.SHELL_ARBITRARY).gate_outside is Gate.HUMAN
    assert report.mcp_servers == ()
    project = [layer for layer in report.layers if layer.scope is Scope.PROJECT]
    assert project[0].trusted is False
    machine.write(".gemini/trustedFolders.json", {str(machine.workspace): "TRUST_FOLDER"})
    trusted = _inspect(machine)
    assert _channel(trusted, Channel.SHELL_ARBITRARY).gate_outside is Gate.NONE
    assert [s.name for s in trusted.mcp_servers] == ["repo"]


def test_without_folder_trust_the_project_always_applies(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {})
    machine.write_workspace(".gemini/settings.json", {"tools": {"allowed": ["run_shell_command"]}})
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is Gate.NONE


def test_macos_seatbelt_sandbox_still_reads_everything(tmp_path: Path) -> None:
    machine = _machine(tmp_path, System.MACOS)
    machine.write(
        ".gemini/settings.json", {"tools": {"sandbox": True, "allowed": ["run_shell_command"]}}
    )
    report = _inspect(machine)
    assert report.policy.sandbox.available is True
    assert report.policy.sandbox.read_only is None
    key = str(machine.home / ".ssh" / "id_ed25519")
    assert reach_of(report.policy, key).reach is Reach.NO_APPROVAL


def test_a_docker_sandbox_sees_only_the_workspace(tmp_path: Path) -> None:
    machine = _machine(tmp_path, GEMINI_SANDBOX="docker")
    machine.write(".gemini/settings.json", {"tools": {"allowed": ["run_shell_command"]}})
    report = _inspect(machine)
    assert report.policy.sandbox.read_only == (str(machine.workspace),)
    key = str(machine.home / ".ssh" / "id_ed25519")
    result = reach_of(report.policy, key)
    assert result.reach is Reach.BLOCKED_BY_RULE  # shell: no mount; file tools: outside the root


def test_mcp_servers_and_trust(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".gemini/settings.json",
        {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                    "trust": True,
                },
                "remote": {
                    "httpUrl": f"https://mcp.example.org/?k={canaries.MARK}",
                    "headers": {"X-Key": canaries.MARK},
                },
            }
        },
    )
    report = _inspect(machine)
    servers = {s.name: s for s in report.mcp_servers}
    assert servers["gh"].package == "@modelcontextprotocol/server-github"
    assert servers["remote"].host == "mcp.example.org"
    assert dict(report.policy.mcp_gates) == {"gh": Gate.NONE, "remote": Gate.HUMAN}
    assert canaries.MARK not in repr(report)


def test_jsonc_comments_are_accepted(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".gemini/settings.json",
        '{\n  // my settings\n  "general": {"defaultApprovalMode": "auto_edit",},\n}\n',
    )
    assert _inspect(machine).mode == "auto_edit"


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".gemini/settings.json", {"security": {"folderTrust": {"enabled": True}}})
    machine.write(".gemini/trustedFolders.json", {})
    machine.write(".gemini/policies/a.toml", "")
    machine.write_workspace(".gemini/settings.json", {})
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        _inspect(machine)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access
