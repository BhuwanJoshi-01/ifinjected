"""opencode: precedence, last-match permissions, external directories, MCP (IFJ-026)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ifinjected.agents.opencode import inspect_opencode
from ifinjected.files import Level, recording
from ifinjected.homes import Scope
from ifinjected.inventory.catalog import load_catalog
from ifinjected.models import Policy, Reach
from ifinjected.orchestrator import inspect_all
from ifinjected.policy.model import Channel, Gate
from ifinjected.policy.reach import reach_of
from ifinjected.trifecta.verdict import Grade
from tests import canaries
from tests.homes import FakeMachine


def _machine(tmp_path: Path) -> FakeMachine:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return machine


def _inspect(machine: FakeMachine) -> Any:
    return inspect_opencode(machine.platform(), Policy(), machine.workspace)


def _channel(report: Any, channel: Channel) -> Any:
    return next((c for c in report.policy.channels if c.channel is channel), None)


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_the_defaults_allow_bash_and_web_fetch(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"$schema": "https://opencode.ai/config.json"})
    report = _inspect(machine)
    assert _channel(report, Channel.SHELL_ARBITRARY).gate_outside is Gate.NONE
    assert report.policy.web_fetch is Gate.NONE
    assert report.policy.sandbox.enabled is False
    key = str(machine.home / ".ssh" / "id_ed25519")
    assert reach_of(report.policy, key).reach is Reach.NO_APPROVAL


def test_read_asks_for_env_files_by_default(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"permission": {"bash": "deny"}})
    report = _inspect(machine)
    env = str(machine.workspace / ".env")
    example = str(machine.workspace / ".env.example")
    source = str(machine.workspace / "src" / "app.py")
    assert reach_of(report.policy, env).reach is Reach.AFTER_APPROVAL
    assert reach_of(report.policy, example).reach is Reach.NO_APPROVAL  # the last match wins
    assert reach_of(report.policy, source).reach is Reach.NO_APPROVAL
    outside = str(machine.home / ".aws" / "credentials")
    assert reach_of(report.policy, outside).reach is Reach.AFTER_APPROVAL  # external_directory asks


@pytest.mark.parametrize(
    ("bash", "gate"),
    [
        ("ask", Gate.HUMAN),
        ({"*": "ask", "git *": "allow"}, Gate.HUMAN),
        ({"*": "ask", "python3 *": "allow"}, Gate.NONE),
        ({"*": "allow", "rm *": "deny"}, Gate.NONE),
    ],
)
def test_bash_pattern_maps(tmp_path: Path, bash: Any, gate: Gate) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"permission": {"bash": bash}})
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is gate


def test_denying_bash_removes_the_shell(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"permission": {"bash": "deny"}})
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY) is None


def test_a_string_permission_applies_to_every_tool(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"permission": "ask"})
    report = _inspect(machine)
    assert _channel(report, Channel.SHELL_ARBITRARY).gate_outside is Gate.HUMAN
    assert report.policy.web_fetch is Gate.HUMAN


def test_the_project_and_managed_files_override_the_users(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.json", {"permission": {"bash": "deny"}})
    machine.write_workspace("opencode.json", {"permission": {"bash": "ask"}})
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is Gate.HUMAN
    machine.write_at(
        machine.root / "etc" / "opencode" / "opencode.json", {"permission": {"bash": "allow"}}
    )
    assert _channel(_inspect(machine), Channel.SHELL_ARBITRARY).gate_outside is Gate.NONE


def test_mcp_servers_in_both_shapes_without_secrets(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".config/opencode/opencode.json",
        {
            "mcp": {
                "servers": {
                    "gh": {
                        "type": "local",
                        "command": ["npx", "-y", "@modelcontextprotocol/server-github"],
                        "environment": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                    }
                }
            }
        },
    )
    machine.write_workspace(
        "opencode.json",
        {
            "mcp": {
                "docs": {"type": "remote", "url": f"https://mcp.example.org/?k={canaries.MARK}"},
                "off": {"type": "local", "command": ["x"], "enabled": False},
            }
        },
    )
    report = _inspect(machine)
    servers = {s.name: s for s in report.mcp_servers}
    assert servers["gh"].package == "@modelcontextprotocol/server-github"
    assert servers["gh"].env_names == ("GITHUB_TOKEN",)
    assert servers["docs"].scope is Scope.PROJECT
    assert servers["off"].approved is False
    assert canaries.MARK not in repr(report)


def test_a_default_opencode_with_credentials_is_an_f(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.add_credentials()
    machine.write(".config/opencode/opencode.json", {})
    snapshot = inspect_all(machine.platform(), Policy(), machine.workspace)
    (trifecta,) = snapshot.trifectas
    assert trifecta.grade is Grade.F


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".config/opencode/opencode.jsonc", "{}")
    machine.write_workspace(".opencode/opencode.json", {})
    machine.write_workspace("opencode.json", {})
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        _inspect(machine)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access
