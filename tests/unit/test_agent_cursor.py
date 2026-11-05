"""Cursor: run modes, read access, sandbox.json, permissions and MCP (IFJ-025)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ifinjected.agents.cursor import inspect_cursor
from ifinjected.files import Level, recording
from ifinjected.homes import Scope, System
from ifinjected.inventory.catalog import load_catalog
from ifinjected.models import Policy, Reach
from ifinjected.policy.model import Channel, Gate
from ifinjected.policy.reach import reach_of
from tests import canaries
from tests.homes import FakeMachine


def _machine(tmp_path: Path, system: System = System.LINUX) -> FakeMachine:
    machine = FakeMachine(tmp_path, system)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return machine


def _inspect(machine: FakeMachine) -> Any:
    return inspect_cursor(machine.platform(), Policy(), machine.workspace)


def _key(machine: FakeMachine) -> str:
    return str(machine.home / ".ssh" / "id_ed25519")


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_auto_review_defaults_read_outside_the_workspace_unasked(tmp_path: Path) -> None:
    machine = _machine(tmp_path, System.MACOS)
    (machine.home / ".cursor").mkdir(parents=True)
    report = _inspect(machine)
    assert report.found
    assert report.mode == "auto-review"
    files, sandboxed, escaped = report.policy.channels
    assert files.gate_outside is Gate.NONE  # Read Access: System
    assert (sandboxed.sandboxed, sandboxed.gate_outside) == (True, Gate.NONE)
    assert (escaped.sandboxed, escaped.gate_outside) == (False, Gate.AUTOMATED)
    assert reach_of(report.policy, _key(machine)).reach is Reach.NO_APPROVAL
    assert "github.com" in report.policy.sandbox.allowed_domains
    assert any("own state" in u for u in report.policy.unknowns)


def test_workspace_read_boundary_asks_and_confines_the_sandbox(tmp_path: Path) -> None:
    machine = _machine(tmp_path, System.MACOS)
    machine.write(".cursor/sandbox.json", {"readBoundary": "workspace"})
    report = _inspect(machine)
    assert report.policy.channels[0].gate_outside is Gate.HUMAN
    result = reach_of(report.policy, _key(machine))
    assert result.reach is Reach.AFTER_APPROVAL  # the classifier-reviewed escape is the easiest


@pytest.mark.parametrize(
    ("mode", "expected"), [("unrestricted", "run-everything"), ("allowlist", "allowlist")]
)
def test_cli_approval_modes(tmp_path: Path, mode: str, expected: str) -> None:
    machine = _machine(tmp_path)
    machine.write(".cursor/cli-config.json", {"approvalMode": mode})
    report = _inspect(machine)
    assert report.mode == expected
    if expected == "run-everything":
        assert not report.policy.sandbox.enabled
        assert all(c.gate_outside is Gate.NONE for c in report.policy.channels)


def test_insecure_none_turns_the_sandbox_off(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write_workspace(".cursor/sandbox.json", {"type": "insecure_none"})
    report = _inspect(machine)
    shell = next(c for c in report.policy.channels if c.channel is Channel.SHELL_ARBITRARY)
    assert (report.policy.sandbox.enabled, shell.gate_outside) == (False, Gate.HUMAN)


def test_read_deny_and_shell_permissions(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".cursor/cli-config.json",
        {"permissions": {"deny": ["Read(~/.ssh/**)", "Shell(*)"], "allow": []}},
    )
    report = _inspect(machine)
    assert [c.channel for c in report.policy.channels] == [Channel.FILE_TOOL]
    assert reach_of(report.policy, _key(machine)).reach is Reach.BLOCKED_BY_RULE


def test_mcp_servers_project_over_user_and_their_gates(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".cursor/mcp.json",
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
        ".cursor/mcp.json", {"mcpServers": {"gh": {"url": "https://api.githubcopilot.com/mcp/"}}}
    )
    machine.write(".cursor/cli-config.json", {"permissions": {"allow": ["Mcp(gh:*)"]}})
    report = _inspect(machine)
    (server,) = report.mcp_servers
    assert (server.scope, server.host) == (Scope.PROJECT, "api.githubcopilot.com")
    assert dict(report.policy.mcp_gates) == {"gh": Gate.NONE}
    assert canaries.MARK not in repr(report)


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    for path in (
        ".cursor/cli-config.json",
        ".cursor/sandbox.json",
        ".cursor/mcp.json",
        ".config/cursor/cli-config.json",
    ):
        machine.write(path, {})
    for path in (".cursor/cli.json", ".cursor/sandbox.json", ".cursor/mcp.json"):
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
