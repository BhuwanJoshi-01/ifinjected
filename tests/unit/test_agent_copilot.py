"""Copilot CLI: settings, approvals, sandbox, MCP and Claude Code's files (IFJ-027)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ifinjected.agents.copilot import inspect_copilot
from ifinjected.files import Level, recording
from ifinjected.homes import Scope
from ifinjected.inventory.catalog import load_catalog
from ifinjected.models import Policy, Reach
from ifinjected.policy.model import Gate
from ifinjected.policy.reach import reach_of
from tests import canaries
from tests.homes import FakeMachine


def _machine(tmp_path: Path) -> FakeMachine:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return machine


def _inspect(machine: FakeMachine) -> Any:
    return inspect_copilot(machine.platform(), Policy(), machine.workspace)


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_manual_mode_asks_outside_trusted_directories(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".copilot/config.json", {"firstLaunchAt": "2026-01-01"})
    report = _inspect(machine)
    files, shell = report.policy.channels
    assert (files.gate_inside, files.gate_outside, shell.gate_outside) == (
        Gate.NONE,
        Gate.HUMAN,
        Gate.HUMAN,
    )
    assert (
        reach_of(report.policy, str(machine.home / ".ssh" / "id_ed25519")).reach
        is Reach.AFTER_APPROVAL
    )
    assert reach_of(report.policy, str(machine.workspace / ".env")).reach is Reach.NO_APPROVAL


def test_allow_all_runs_everything_unasked(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".copilot/settings.json", {"permissionMode": "allow-all"})
    report = _inspect(machine)
    assert all(c.gate_outside is Gate.NONE for c in report.policy.channels)
    assert report.policy.web_fetch is Gate.NONE


def test_the_sandbox_gets_your_git_credentials_unless_told_not_to(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".copilot/settings.json",
        {
            "sandbox": {
                "enabled": True,
                "userPolicy": {
                    "filesystem": {"deniedPaths": ["~/.ssh"]},
                    "network": {"allowedHosts": ["github.com"]},
                },
            }
        },
    )
    report = _inspect(machine)
    assert str(machine.home / ".ssh") in report.policy.sandbox.read_deny
    assert report.policy.sandbox.allowed_domains == ("github.com",)
    assert any("git and gh credentials" in note for note in report.notes)
    assert report.policy.sandbox.escape_hatches == ("sandbox.allowBypass",)


def test_repository_settings_override_the_users(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".copilot/settings.json", {"permissionMode": "manual"})
    machine.write_workspace(".github/copilot/settings.json", {"permissionMode": "allow-all"})
    assert _inspect(machine).mode == "allow-all"


def test_mcp_servers_and_claude_code_hooks_from_the_repository(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".copilot/mcp-config.json",
        {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                }
            }
        },
    )
    machine.write_workspace(
        ".mcp.json", {"mcpServers": {"shared": {"command": "node", "args": ["srv.js"]}}}
    )
    machine.write_workspace(
        ".claude/settings.json",
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "./boot.sh"}]}]}},
    )
    report = _inspect(machine)
    assert {(s.name, s.scope) for s in report.mcp_servers} == {
        ("gh", Scope.USER),
        ("shared", Scope.PROJECT),
    }
    assert [(h.event, h.program, h.scope) for h in report.hooks] == [
        ("SessionStart", "boot.sh", Scope.PROJECT)
    ]
    assert canaries.MARK not in repr(report)


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    for path in (
        ".copilot/settings.json",
        ".copilot/mcp-config.json",
        ".copilot/permissions-config.json",
    ):
        machine.write(path, {})
    for path in (
        ".github/copilot/settings.json",
        ".github/copilot/settings.local.json",
        ".github/mcp.json",
        ".mcp.json",
        ".claude/settings.json",
    ):
        machine.write_workspace(path, {})
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        _inspect(machine)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access
