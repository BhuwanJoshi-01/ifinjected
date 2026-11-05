"""Claude Code: layers, trust, modes, rules, sandbox, MCP servers and hooks (IFJ-022)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ifinjected.agents.base import load_facts
from ifinjected.agents.claude_code import inspect_claude_code
from ifinjected.files import Level, recording
from ifinjected.homes import Scope, System, claude_managed_dir
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


def _settings(machine: FakeMachine, data: dict[str, Any], scope: str = "user") -> None:
    if scope == "user":
        machine.write(".claude/settings.json", data)
    elif scope == "project":
        machine.write_workspace(".claude/settings.json", data)
    else:
        machine.write_workspace(".claude/settings.local.json", data)


def _trust(machine: FakeMachine, trusted: bool, **project: Any) -> None:
    state = {"projects": {str(machine.workspace): {"hasTrustDialogAccepted": trusted, **project}}}
    machine.write(".claude.json", state)


def _inspect(machine: FakeMachine, **policy: Any) -> Any:
    return inspect_claude_code(machine.platform(), Policy(**policy), machine.workspace)


def _gates(report: Any) -> dict[Channel, tuple[Gate, Gate]]:
    return {
        c.channel: (c.gate_inside, c.gate_outside)
        for c in report.policy.channels
        if c.sandboxed is not None
    }


def _key(machine: FakeMachine) -> str:
    return str(machine.home / ".ssh" / "id_ed25519")


def test_not_found_without_any_trace(tmp_path: Path) -> None:
    assert _inspect(_machine(tmp_path)).found is False


def test_the_defaults_of_manual_mode(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {})
    report = _inspect(machine)
    assert report.found
    assert report.mode == "default"
    channels = [(c.channel, c.gate_inside, c.gate_outside) for c in report.policy.channels]
    assert channels == [
        (Channel.FILE_TOOL, Gate.NONE, Gate.HUMAN),
        (Channel.SHELL_RECOGNIZED, Gate.NONE, Gate.NONE),  # cat runs without a prompt
        (Channel.SHELL_ARBITRARY, Gate.HUMAN, Gate.HUMAN),
    ]
    # `cat ~/.ssh/id_ed25519` needs nobody's approval in Manual mode.
    assert reach_of(report.policy, _key(machine)).reach is Reach.NO_APPROVAL


def test_a_deny_rule_covers_cat_but_not_a_script(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
    report = _inspect(machine)
    rule = report.policy.rules[0]
    assert rule.pattern == str(machine.home / ".ssh" / "**")
    assert rule.source.line == 4
    result = reach_of(report.policy, _key(machine))
    assert result.reach is Reach.AFTER_APPROVAL  # a Python one-liner still works, after a prompt
    assert result.bypassed == rule


def test_an_interpreter_allow_rule_makes_the_deny_rule_bypassable(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(
        machine,
        {"permissions": {"allow": ["Bash(python3 *)"], "deny": ["Read(~/.ssh/**)"]}},
    )
    result = reach_of(_inspect(machine).policy, _key(machine))
    assert result.reach is Reach.BYPASSABLE_RULE
    assert result.via is not None
    assert result.via.channel.channel is Channel.SHELL_ARBITRARY


@pytest.mark.parametrize(
    "rule", ["Bash", "Bash(*)", "Bash(node:*)", "Bash(npm run *)", "Bash(uv run *)"]
)
def test_broad_bash_allow_rules_open_arbitrary_commands(tmp_path: Path, rule: str) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"allow": [rule]}})
    arbitrary = next(
        c for c in _inspect(machine).policy.channels if c.channel is Channel.SHELL_ARBITRARY
    )
    assert arbitrary.gate_outside is Gate.NONE


def test_a_narrow_bash_allow_rule_does_not(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"allow": ["Bash(git status)", "Bash(npm test)"]}})
    arbitrary = next(
        c for c in _inspect(machine).policy.channels if c.channel is Channel.SHELL_ARBITRARY
    )
    assert arbitrary.gate_outside is Gate.HUMAN


def test_denying_bash_entirely_removes_the_shell(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"deny": ["Bash", "Read(~/.ssh/**)"]}})
    report = _inspect(machine)
    assert [c.channel for c in report.policy.channels] == [Channel.FILE_TOOL]
    assert reach_of(report.policy, _key(machine)).reach is Reach.BLOCKED_BY_RULE


@pytest.mark.parametrize(
    ("mode", "outside"),
    [
        ("bypassPermissions", Gate.NONE),
        ("auto", Gate.AUTOMATED),
        ("dontAsk", Gate.DENIED),
        ("acceptEdits", Gate.HUMAN),
        ("manual", Gate.HUMAN),
    ],
)
def test_permission_modes_set_the_file_tool_gate(tmp_path: Path, mode: str, outside: Gate) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"defaultMode": mode}})
    report = _inspect(machine)
    file_tool = report.policy.channels[0]
    assert file_tool.gate_outside is outside


def test_project_files_cannot_set_bypass_or_auto_mode(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _trust(machine, True)
    _settings(machine, {"permissions": {"defaultMode": "bypassPermissions"}}, scope="project")
    _settings(machine, {"permissions": {"defaultMode": "auto"}}, scope="local")
    assert _inspect(machine).mode == "default"


def test_the_most_authoritative_layer_sets_the_mode(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _trust(machine, True)
    _settings(machine, {"permissions": {"defaultMode": "bypassPermissions"}})
    _settings(machine, {"permissions": {"defaultMode": "plan"}}, scope="project")
    report = _inspect(machine)
    assert report.mode == "plan"
    managed = claude_managed_dir(machine.platform())
    machine.write_at(
        managed / "managed-settings.d" / "10-mode.json", {"permissions": {"defaultMode": "dontAsk"}}
    )
    assert _inspect(machine).mode == "dontAsk"


def test_project_allow_rules_wait_for_trust_but_deny_rules_do_not(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(
        machine,
        {"permissions": {"allow": ["Bash(python3 *)"], "deny": ["Read(./.env)"]}},
        scope="project",
    )
    _trust(machine, False)
    untrusted = _inspect(machine)
    arbitrary = next(c for c in untrusted.policy.channels if c.channel is Channel.SHELL_ARBITRARY)
    assert arbitrary.gate_outside is Gate.HUMAN
    assert [r.decision for r in untrusted.policy.rules] == [Gate.DENIED]
    assert untrusted.layers[0].trusted is False
    _trust(machine, True)
    arbitrary = next(
        c for c in _inspect(machine).policy.channels if c.channel is Channel.SHELL_ARBITRARY
    )
    assert arbitrary.gate_outside is Gate.NONE


@pytest.mark.parametrize(
    ("scope", "rule", "expected"),
    [
        ("user", "Read(//etc/shadow)", "/etc/shadow"),
        ("user", "Read(~/.aws/**)", "~/.aws/**"),
        ("user", "Read(/secrets/**)", "~/.claude/secrets/**"),
        ("project", "Read(/secrets/**)", "WS/secrets/**"),
        ("project", "Read(./config/prod.json)", "WS/config/prod.json"),
        ("project", "Read(.env)", "WS/**/.env"),
        ("project", "Read(secrets/**)", "WS/**/secrets/**"),
    ],
)
def test_read_rules_anchor_like_claude_code(
    tmp_path: Path, scope: str, rule: str, expected: str
) -> None:
    machine = _machine(tmp_path)
    _trust(machine, True)
    _settings(machine, {"permissions": {"deny": [rule]}}, scope=scope)
    pattern = _inspect(machine).policy.rules[0].pattern
    want = expected.replace("WS", str(machine.workspace)).replace("~", str(machine.home))
    assert Path(pattern) == Path(want)


def test_a_bare_read_rule_covers_everything(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"deny": ["Read", "Bash"]}})
    report = _inspect(machine)
    assert reach_of(report.policy, _key(machine)).reach is Reach.BLOCKED_BY_RULE


def test_block_reads_outside_working_directories(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"blockReadsOutsideWorkingDirectories": True}})
    file_tool, recognized, _ = _inspect(machine).policy.channels
    assert file_tool.gate_outside is Gate.DENIED
    assert recognized.gate_outside is Gate.HUMAN


def test_additional_directories_count_as_working_directories(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"permissions": {"additionalDirectories": ["~/.aws"]}})
    report = _inspect(machine)
    assert str(machine.home / ".aws") in report.policy.working_dirs


# --- the sandbox ----------------------------------------------------------------------------


def _with_bwrap(machine: FakeMachine) -> None:
    machine.write_at(machine.root / "usr" / "bin" / "bwrap", b"\x7fELF")


def test_the_sandbox_runs_commands_without_asking_and_still_reads_your_keys(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _with_bwrap(machine)
    _settings(machine, {"sandbox": {"enabled": True}})
    report = _inspect(machine)
    sandbox = report.policy.sandbox
    assert (sandbox.enabled, sandbox.available) == (True, True)
    arbitrary = report.policy.channels[2]
    assert (arbitrary.sandboxed, arbitrary.gate_outside) == (
        True,
        Gate.NONE,
    )  # autoAllowBashIfSandboxed
    assert report.policy.channels[3].note == "a command retried outside the sandbox after a prompt"
    result = reach_of(report.policy, _key(machine))
    assert result.reach is Reach.NO_APPROVAL  # the sandbox reads most of the machine


def test_read_deny_rules_become_sandbox_denials(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _with_bwrap(machine)
    _settings(
        machine,
        {
            "permissions": {"deny": ["Read(~/.ssh/**)"]},
            "sandbox": {"enabled": True, "allowUnsandboxedCommands": False},
        },
    )
    report = _inspect(machine)
    assert str(machine.home / ".ssh" / "**") in report.policy.sandbox.read_deny
    assert reach_of(report.policy, _key(machine)).reach is Reach.BLOCKED_BY_RULE


def test_sandbox_deny_read_and_network_settings(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _with_bwrap(machine)
    _settings(
        machine,
        {
            "sandbox": {
                "enabled": True,
                "filesystem": {"denyRead": ["~/.aws"]},
                "network": {"allowedDomains": ["github.com"]},
                "excludedCommands": ["docker"],
            }
        },
    )
    sandbox = _inspect(machine).policy.sandbox
    assert str(machine.home / ".aws") in sandbox.read_deny
    assert sandbox.allowed_domains == ("github.com",)
    assert "excludedCommands: docker" in sandbox.escape_hatches


def test_a_sandbox_without_bubblewrap_protects_nothing(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(machine, {"sandbox": {"enabled": True}})
    report = _inspect(machine)
    assert report.policy.sandbox.available is False
    assert not any(c.sandboxed for c in report.policy.channels)
    assert any("cannot run here" in note for note in report.notes)


def test_native_windows_has_no_sandbox(tmp_path: Path) -> None:
    machine = _machine(tmp_path, System.WINDOWS)
    _settings(machine, {"sandbox": {"enabled": True}})
    assert _inspect(machine).policy.sandbox.available is False


# --- MCP servers and hooks ------------------------------------------------------------------


def test_mcp_servers_of_every_scope_without_their_secrets(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".claude.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-github",
                        "--token",
                        canaries.GH_TOKEN,
                    ],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": canaries.GH_TOKEN},
                },
                "docs": {
                    "type": "http",
                    "url": f"https://mcp.example.org/x?key={canaries.MARK}",
                    "headers": {"Authorization": f"Bearer {canaries.MARK}"},
                },
            },
            "projects": {
                str(machine.workspace): {
                    "hasTrustDialogAccepted": True,
                    "mcpServers": {"local-db": {"command": "/opt/bin/db-mcp"}},
                    "enabledMcpjsonServers": ["approved"],
                    "disabledMcpjsonServers": ["off"],
                }
            },
        },
    )
    machine.write_workspace(
        ".mcp.json",
        {
            "mcpServers": {
                "approved": {"command": "uvx", "args": ["x-mcp"]},
                "off": {"command": "y"},
                "pending": {"command": "z", "env": {"API_KEY": canaries.MCP_ENV_VALUE}},
            }
        },
    )
    report = _inspect(machine)
    servers = {s.name: s for s in report.mcp_servers}
    assert (servers["github"].program, servers["github"].package) == (
        "npx",
        "@modelcontextprotocol/server-github",
    )
    assert servers["github"].env_names == ("GITHUB_PERSONAL_ACCESS_TOKEN",)
    assert (servers["docs"].transport, servers["docs"].host) == ("http", "mcp.example.org")
    assert servers["docs"].header_names == ("Authorization",)
    assert servers["local-db"].scope is Scope.LOCAL
    assert (servers["approved"].approved, servers["off"].approved, servers["pending"].approved) == (
        True,
        False,
        None,
    )
    assert servers["github"].source is not None
    assert servers["github"].source.line is not None
    assert canaries.MARK not in repr(report)


def test_enable_all_project_mcp_servers_approves_them(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _trust(machine, True)
    _settings(machine, {"enableAllProjectMcpServers": True})
    machine.write_workspace(".mcp.json", {"mcpServers": {"anything": {"command": "x"}}})
    assert _inspect(machine).mcp_servers[0].approved is True


def test_hooks_are_recorded_by_program_only(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _trust(machine, True)
    _settings(
        machine,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"/usr/local/bin/guard --token {canaries.MARK}",
                            }
                        ],
                    }
                ]
            }
        },
        scope="project",
    )
    report = _inspect(machine)
    assert [(h.event, h.program, h.scope) for h in report.hooks] == [
        ("PreToolUse", "guard", Scope.PROJECT)
    ]
    assert canaries.MARK not in repr(report)


def test_an_unreadable_layer_is_reported_and_makes_the_result_uncertain(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(".claude/settings.json", "{ not json")
    report = _inspect(machine)
    assert report.layers[0].skipped is not None
    assert report.policy.unknowns
    assert reach_of(report.policy, _key(machine)).uncertain


def test_env_names_and_api_key_helper_are_shown_without_values(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _settings(
        machine,
        {
            "env": {"ANTHROPIC_BASE_URL": canaries.MARK},
            "apiKeyHelper": f"/bin/get-key {canaries.MARK}",
        },
    )
    report = _inspect(machine)
    settings = {name: value for name, value, _ in report.settings}
    assert settings["env (names)"] == "ANTHROPIC_BASE_URL"
    assert settings["apiKeyHelper"] == "get-key"
    assert canaries.MARK not in repr(report)


def test_every_fact_cited_has_a_source() -> None:
    facts = load_facts()
    assert all(f.source_url.startswith("https://") for f in facts.values())
    assert {"claude.readonly_commands", "claude.sandbox_reads", "claude.deny_scope"} <= set(facts)


def test_every_look_is_declared_in_the_catalog(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    _with_bwrap(machine)
    _trust(machine, True)
    _settings(machine, {"sandbox": {"enabled": True}})
    _settings(machine, {}, scope="project")
    machine.write_workspace(".mcp.json", {"mcpServers": {}})
    managed = claude_managed_dir(machine.platform())
    machine.write_at(managed / "managed-settings.d" / "a.json", {})
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        _inspect(machine)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access


def test_state_file_values_that_are_not_needed_are_not_kept(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    machine.write(
        ".claude.json",
        json.loads(
            json.dumps(
                {
                    "oauthAccount": {"emailAddress": f"{canaries.MARK}@x.org"},
                    "projects": {str(machine.workspace): {"lastSessionFirstPrompt": canaries.MARK}},
                }
            )
        ),
    )
    assert canaries.MARK not in repr(_inspect(machine))
