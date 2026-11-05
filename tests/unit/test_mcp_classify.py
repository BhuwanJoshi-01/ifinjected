"""What configured MCP servers can do, from the sourced catalog (IFJ-030)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.agents.base import McpServer, describe_command
from ifinjected.agents.claude_code import inspect_claude_code
from ifinjected.homes import Scope
from ifinjected.models import AgentId, Policy, Reach
from ifinjected.policy.model import Channel, Gate
from ifinjected.policy.reach import reach_of
from ifinjected.trifecta.classify import Capability, classify, load_mcp_catalog
from tests.homes import FakeMachine


def _server(**kwargs: object) -> McpServer:
    values: dict[str, object] = {
        "agent": AgentId.CLAUDE_CODE,
        "name": "x",
        "scope": Scope.USER,
        "transport": "stdio",
    }
    values.update(kwargs)
    return McpServer(**values)  # type: ignore[arg-type]


def test_every_catalog_entry_is_sourced_and_unique() -> None:
    catalog = load_mcp_catalog()
    assert len({e.id for e in catalog}) == len(catalog)
    assert all(e.source.startswith("https://") and e.note for e in catalog)


@pytest.mark.parametrize(
    ("package", "expected"),
    [
        (
            "@modelcontextprotocol/server-github",
            {"untrusted_input", "exfiltration", "private_data"},
        ),
        ("@modelcontextprotocol/server-filesystem@2025.1.1", {"reads_files", "writes_files"}),
        ("mcp-server-fetch==2025.4.7", {"untrusted_input", "exfiltration"}),
        ("@playwright/mcp@latest", {"untrusted_input", "exfiltration"}),
        ("awslabs.aws-documentation-mcp-server", {"private_data", "exfiltration"}),
        ("@modelcontextprotocol/server-memory", set()),
    ],
)
def test_known_packages(package: str, expected: set[str]) -> None:
    result = classify(_server(program="npx", package=package))
    assert result.known
    assert {c.value for c in result.capabilities} == expected


def test_remote_servers_match_by_host() -> None:
    result = classify(_server(transport="http", host="api.githubcopilot.com"))
    assert (result.known, result.local) == (True, False)
    assert result.has(Capability.EXFILTRATION)
    assert (
        classify(_server(transport="http", host="evil-api.githubcopilot.com.example")).known
        is False
    )


def test_an_unknown_server_is_unknown_not_harmless() -> None:
    result = classify(_server(program="my-mcp"))
    assert (result.known, result.local, result.capabilities) == (False, True, frozenset())


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        (
            "docker",
            ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"],
            ("docker", "ghcr.io/github/github-mcp-server"),
        ),
        (
            "docker",
            ["run", "--rm", "registry:5000/team/mcp:1.2"],
            ("docker", "registry:5000/team/mcp"),
        ),
        ("uvx", ["--python", "3.11", "blender-mcp"], ("uvx", "blender-mcp")),
        ("uvx", ["--from", "mcp-server-fetch", "mcp-server-fetch"], ("uvx", "mcp-server-fetch")),
        ("npx", ["-y", "-p", "@x/pkg", "bin"], ("npx", "@x/pkg")),
        ("/usr/local/bin/node", ["server.js", "--token", "abc"], ("node", None)),
    ],
)
def test_describe_command(command: str, args: list[str], expected: tuple[str, str | None]) -> None:
    assert describe_command(command, args) == expected


def _claude_with_filesystem_server(
    tmp_path: Path, allow: list[str] | None = None
) -> tuple[FakeMachine, object]:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    machine.write(
        ".claude/settings.json",
        {"permissions": {"deny": ["Read(~/.ssh/**)", "Bash"], "allow": allow or []}},
    )
    machine.write(
        ".claude.json",
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                }
            }
        },
    )
    return machine, inspect_claude_code(machine.platform(), Policy(), machine.workspace)


def test_a_filesystem_server_walks_around_read_rules(tmp_path: Path) -> None:
    machine, report = _claude_with_filesystem_server(tmp_path, allow=["mcp__fs"])
    channels = report.policy.channels  # type: ignore[attr-defined]
    mcp = [c for c in channels if c.channel is Channel.MCP]
    assert [(c.gate_outside, c.sandboxed, c.note) for c in mcp] == [
        (Gate.NONE, False, "MCP server fs")
    ]
    result = reach_of(report.policy, str(machine.home / ".ssh" / "id_ed25519"))  # type: ignore[attr-defined]
    assert result.reach is Reach.BYPASSABLE_RULE
    assert result.via is not None
    assert result.via.channel.channel is Channel.MCP


def test_an_mcp_server_asks_before_its_tools_run_by_default(tmp_path: Path) -> None:
    machine, report = _claude_with_filesystem_server(tmp_path)
    result = reach_of(report.policy, str(machine.home / ".ssh" / "id_ed25519"))  # type: ignore[attr-defined]
    assert result.reach is Reach.AFTER_APPROVAL
