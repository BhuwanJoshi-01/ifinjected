"""Codex: layers, sandbox modes, permission profiles, environment and MCP (IFJ-023)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ifinjected.agents.codex import inspect_codex
from ifinjected.files import Level, recording
from ifinjected.homes import Scope, System
from ifinjected.inventory.catalog import load_catalog
from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import Policy, Reach, SensitiveItem, Severity
from ifinjected.orchestrator import inspect_all
from ifinjected.policy.exposure import exposure_of
from ifinjected.policy.model import Gate
from ifinjected.policy.reach import reach_of
from ifinjected.trifecta.verdict import Grade
from tests import canaries
from tests.homes import FakeMachine


def _machine(tmp_path: Path, system: System = System.LINUX) -> FakeMachine:
    machine = FakeMachine(tmp_path, system)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    return machine


def _config(machine: FakeMachine, text: str, *, trusted: bool = True) -> None:
    key = str(machine.workspace).replace("\\", "\\\\")  # a TOML basic string
    trust = f'\n[projects."{key}"]\ntrust_level = "trusted"\n'
    machine.write(".codex/config.toml", text + (trust if trusted else ""))


def _inspect(machine: FakeMachine) -> Any:
    return inspect_codex(machine.platform(), Policy(), machine.workspace)


def _key(machine: FakeMachine) -> str:
    return str(machine.home / ".ssh" / "id_ed25519")


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_a_trusted_workspace_defaults_to_workspace_write_and_on_request(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, 'model = "gpt-5.5"\n')
    report = _inspect(machine)
    assert report.mode == "workspace-write + on-request"
    sandboxed, escalated = report.policy.channels
    assert (sandboxed.sandboxed, sandboxed.gate_outside) == (True, Gate.NONE)
    assert (escalated.sandboxed, escalated.gate_outside) == (False, Gate.HUMAN)
    # The sandbox reads the whole disk: cat ~/.ssh/id_ed25519 needs no approval.
    result = reach_of(report.policy, _key(machine))
    assert result.reach is Reach.NO_APPROVAL
    assert result.via is not None
    assert result.via.channel.sandboxed


def test_an_untrusted_workspace_ignores_its_project_config(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, "", trusted=False)
    machine.write_workspace(".codex/config.toml", 'sandbox_mode = "danger-full-access"\n')
    report = _inspect(machine)
    assert report.mode == "read-only + on-request"
    project = [layer for layer in report.layers if layer.scope is Scope.PROJECT]
    assert project[0].trusted is False


def test_a_trusted_project_config_wins(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, 'sandbox_mode = "read-only"\n')
    machine.write_workspace(
        ".codex/config.toml", 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n'
    )
    assert _inspect(machine).mode == "danger-full-access + never"


def test_full_access_without_approvals_is_an_f(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.add_credentials()
    _config(machine, 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n')
    snapshot = inspect_all(machine.platform(), Policy(agents=()), machine.workspace)
    codex = next(t for t in snapshot.trifectas if t.agent.value == "codex")
    assert codex.grade is Grade.F


def test_network_access_in_the_sandbox(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, "[sandbox_workspace_write]\nnetwork_access = true\n")
    assert _inspect(machine).policy.sandbox.network.value == "open"


def test_a_permissions_profile_denies_reads_in_the_sandbox(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(
        machine,
        'default_permissions = "dev"\n[permissions.dev.filesystem]\n'
        '"~/.ssh" = "deny"\n":root" = "read"\n',
    )
    report = _inspect(machine)
    assert str(machine.home / ".ssh") in report.policy.sandbox.read_deny
    result = reach_of(report.policy, _key(machine))
    assert result.reach is Reach.AFTER_APPROVAL  # only by going outside the sandbox, if approved


def test_a_profile_selected_in_config(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(
        machine,
        'profile = "yolo"\nsandbox_mode = "read-only"\n'
        '[profiles.yolo]\nsandbox_mode = "danger-full-access"\n',
    )
    assert _inspect(machine).mode.startswith("danger-full-access")


@pytest.mark.parametrize(
    ("setting", "inherited"),
    [
        ("", True),
        ("[shell_environment_policy]\nignore_default_excludes = false\n", False),
        ('[shell_environment_policy]\ninherit = "none"\n', False),
    ],
)
def test_secret_named_variables_are_inherited_unless_excluded(
    tmp_path: Path, setting: str, inherited: bool
) -> None:
    machine = _machine(tmp_path)
    _config(machine, setting)
    report = _inspect(machine)
    assert report.policy.inherits_secret_env is inherited
    item = SensitiveItem("env.variables", "env", ENVIRONMENT, Severity.HIGH)
    exposure = exposure_of(report.policy, item)
    assert exposure.reach is (Reach.NO_APPROVAL if inherited else Reach.BLOCKED_BY_RULE)


def test_mcp_servers_and_their_approval_modes(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(
        machine,
        "[mcp_servers.github]\n"
        'command = "npx"\n'
        f'args = ["-y", "@modelcontextprotocol/server-github", "--token", "{canaries.GH_TOKEN}"]\n'
        f'env = {{ GITHUB_TOKEN = "{canaries.GH_TOKEN}" }}\n'
        'default_tools_approval_mode = "auto"\n'
        "[mcp_servers.docs]\n"
        'url = "https://mcp.example.org/x"\n'
        'bearer_token_env_var = "DOCS_TOKEN"\n'
        "[mcp_servers.off]\n"
        'command = "x"\n'
        "enabled = false\n",
    )
    report = _inspect(machine)
    servers = {s.name: s for s in report.mcp_servers}
    assert servers["github"].package == "@modelcontextprotocol/server-github"
    assert servers["github"].scope is Scope.USER
    assert servers["github"].env_names == ("GITHUB_TOKEN",)
    assert servers["docs"].host == "mcp.example.org"
    assert servers["off"].approved is False
    assert dict(report.policy.mcp_gates) == {"github": Gate.NONE, "docs": Gate.HUMAN}
    assert canaries.MARK not in repr(report)


def test_requirements_and_notify_are_reported(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, 'notify = ["/usr/local/bin/notifier", "--x"]\n')
    machine.write_at(
        machine.root / "etc" / "codex" / "requirements.toml",
        'allowed_sandbox_modes = ["read-only"]\n',
    )
    report = _inspect(machine)
    settings = {name: value for name, value, _ in report.settings}
    assert settings["allowed sandbox modes (managed)"] == "read-only"
    assert [(h.event, h.program) for h in report.hooks] == [("notify", "notifier")]


def test_windows_requirements_live_in_program_data(tmp_path: Path) -> None:
    machine = _machine(tmp_path, System.WINDOWS)
    machine.write_at(
        Path(machine.platform().program_data) / "OpenAI" / "Codex" / "requirements.toml",
        'allowed_approval_policies = ["on-request"]\n',
    )
    _config(machine, "")
    assert any(layer.scope is Scope.MANAGED for layer in _inspect(machine).layers)


def test_an_unreadable_config_is_uncertain(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".codex/config.toml", "sandbox_mode = \n")
    report = _inspect(machine)
    assert report.policy.unknowns
    assert report.layers[0].skipped


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _config(machine, 'profile = "p"\n')
    machine.write(".codex/p.config.toml", 'sandbox_mode = "read-only"\n')
    machine.write_workspace(".codex/config.toml", "")
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        _inspect(machine)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access
