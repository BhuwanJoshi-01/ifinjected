"""INPUT, EXFIL, MCP, HOOK and TRIFECTA rules (IFJ-030, IFJ-031)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ifinjected.models import Finding, Policy, Severity, Status
from ifinjected.orchestrator import diagnose, inspect_all
from tests import canaries
from tests.homes import FakeMachine


def _findings(
    machine: FakeMachine, settings: dict[str, Any], state: dict[str, Any] | None = None
) -> dict[str, list[Finding]]:
    machine.workspace.mkdir(parents=True, exist_ok=True)
    machine.write(".claude/settings.json", settings)
    if state is not None:
        machine.write(".claude.json", state)
    snapshot = diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))
    found: dict[str, list[Finding]] = {}
    for finding in snapshot.findings:
        found.setdefault(finding.id, []).append(finding)
    return found


GITHUB = {
    "github": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
    }
}


def test_bypass_mode_with_credentials_is_an_ungated_trifecta(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    found = _findings(machine, {"permissions": {"defaultMode": "bypassPermissions"}})
    (trifecta,) = found["IFJ-TRIFECTA-001"]
    assert (trifecta.status, trifecta.severity) == (Status.FAIL, Severity.HIGH)
    assert "grade F" in trifecta.summary
    legs = {e.key: e.value for e in trifecta.evidence}
    assert set(legs) == {"private data", "untrusted input", "a way out"}
    assert found["IFJ-EXFIL-001"][0].severity is Severity.HIGH  # curl anywhere, unasked
    assert found["IFJ-EXFIL-003"]  # WebFetch unasked
    assert found["IFJ-INPUT-001"]


def test_manual_mode_is_a_gated_trifecta_that_never_fails_strict(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    found = _findings(machine, {})
    (trifecta,) = found["IFJ-TRIFECTA-002"]
    assert trifecta.status is Status.WARN
    assert "IFJ-TRIFECTA-001" not in found
    assert found["IFJ-EXFIL-001"][0].severity is Severity.MEDIUM  # curl, after a prompt


def test_github_server_brings_input_and_a_way_out(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    found = _findings(machine, {"permissions": {"allow": ["mcp__github"]}}, {"mcpServers": GITHUB})
    assert found["IFJ-INPUT-002"][0].evidence[0].value == "github"
    assert found["IFJ-EXFIL-004"][0].severity is Severity.HIGH  # allowed: nobody asks
    assert found["IFJ-MCP-003"]
    assert found["IFJ-MCP-002"][0].summary.endswith("at every start")  # npx without a version
    assert [f.severity for f in found["IFJ-MCP-001"]] == [Severity.LOW]  # known, local
    assert canaries.MARK not in repr(found)


def test_pinned_and_unknown_servers(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    found = _findings(
        machine,
        {},
        {
            "mcpServers": {
                "pinned": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-memory@2025.4.25"],
                },
                "mine": {"command": "/opt/my-mcp/bin/server"},
            }
        },
    )
    assert "IFJ-MCP-002" not in found
    unknown = [f for f in found["IFJ-MCP-001"] if "not in ifinjected's catalog" in f.summary]
    assert [f.severity for f in unknown] == [Severity.MEDIUM]


def test_repository_hooks_and_servers_are_repository_code(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    machine.write_workspace(
        ".claude/settings.json",
        {
            "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "./setup.sh"}]}]},
            "enableAllProjectMcpServers": True,
        },
    )
    machine.write_workspace(
        ".mcp.json", {"mcpServers": {"repo-tool": {"command": "node", "args": ["tool.js"]}}}
    )
    state = {"projects": {str(machine.workspace): {"hasTrustDialogAccepted": True}}}
    found = _findings(
        machine,
        {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "notify-send"}]}]}},
        state,
    )
    repository = [f.summary for f in found["IFJ-INPUT-003"]]
    assert any("SessionStart hook" in s for s in repository)
    assert any("repo-tool" in s for s in repository)
    assert [f.summary for f in found["IFJ-HOOK-001"]] == [
        "Claude Code runs notify-send on Stop, outside the sandbox"
    ]


def test_sandbox_allowlists_with_upload_hosts(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write_at(machine.root / "usr" / "bin" / "bwrap", b"x")
    found = _findings(
        machine,
        {
            "sandbox": {
                "enabled": True,
                "allowUnsandboxedCommands": False,
                "network": {
                    "allowedDomains": ["registry.npmjs.org", "github.com", "*.s3.amazonaws.com"]
                },
            }
        },
    )
    (finding,) = found["IFJ-EXFIL-002"]
    assert "github.com" in finding.summary
    assert "registry.npmjs.org" not in finding.summary
    assert "IFJ-EXFIL-001" not in found  # the shell is sandboxed, with no unsandboxed retry


def test_a_contained_agent_has_no_trifecta_finding(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    found = _findings(
        machine,
        {"permissions": {"deny": ["Bash", "WebFetch", "WebSearch"]}},
    )
    assert not {"IFJ-TRIFECTA-001", "IFJ-TRIFECTA-002"} & set(found)
