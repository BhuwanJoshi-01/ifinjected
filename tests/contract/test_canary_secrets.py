"""Planted secrets must reach no output: terminal, JSON, Markdown, SARIF or errors (IFJ-002).

The fake machine plants a canary in every credential, in MCP server arguments, env and
headers, in hook commands, in .env values and in environment variable *values*. Every
canary carries one mark, so a single search covers them all. Some look like real tokens
(the redactor would catch them) and some do not (only the parsers dropping them helps).
"""

from __future__ import annotations

import base64
import dataclasses
from pathlib import Path

import pytest
from rich.console import Console

from ifinjected.homes import Platform
from ifinjected.models import Policy
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.privacy import RedactionContext, redacted_with_counts
from ifinjected.reports.agents import render_agents
from ifinjected.reports.formats import render_json, render_markdown, render_sarif
from ifinjected.reports.scan import render_scan
from ifinjected.reports.terminal import render_inventory
from tests import canaries
from tests.homes import FakeMachine
from tests.unit.test_cli import run_main


def _messy(tmp_path: Path) -> FakeMachine:
    machine = FakeMachine(
        tmp_path,
        env={
            "OPENAI_API_KEY": canaries.OPENAI_KEY,
            "BW_SESSION": canaries.SESSION,
            "MY_SECRET": canaries.ENV_VALUE,
        },
    )
    machine.add_credentials()
    machine.write(
        ".claude/settings.json",
        {
            "permissions": {"defaultMode": "bypassPermissions", "deny": ["Read(~/.ssh/**)"]},
            "env": {"ANTHROPIC_API_KEY": canaries.ANTHROPIC_KEY},
            "apiKeyHelper": f"/bin/key --secret {canaries.MARK}",
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "command", "command": f"notify --token {canaries.MARK}"}]}
                ]
            },
        },
    )
    machine.write(
        ".claude.json",
        {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github", canaries.GH_TOKEN],
                    "env": {"GITHUB_TOKEN": canaries.GH_TOKEN},
                },
                "remote": {
                    "type": "http",
                    "url": f"https://u:{canaries.MARK}@mcp.example.org/?key={canaries.MARK}",
                    "headers": {"Authorization": f"Bearer {canaries.MARK}"},
                },
            }
        },
    )
    machine.write(
        ".codex/config.toml",
        f'[mcp_servers.x]\ncommand = "uvx"\nargs = ["x-mcp", "--key", "{canaries.MARK}"]\n'
        f'env = {{ API_KEY = "{canaries.MCP_ENV_VALUE}" }}\n',
    )
    machine.write(
        ".config/opencode/opencode.json",
        {
            "mcp": {
                "y": {
                    "type": "local",
                    "command": ["y", canaries.MARK],
                    "environment": {"K": canaries.MARK},
                }
            }
        },
    )
    machine.write(
        ".gemini/settings.json",
        {"mcpServers": {"z": {"command": "z", "env": {"Z": canaries.MARK}}}},
    )
    machine.write(".gemini/oauth_creds.json", {"refresh_token": canaries.GOOGLE_REFRESH})
    return machine


def _assert_clean(text: str, machine: FakeMachine) -> None:
    assert canaries.MARK not in text
    for canary in canaries.ALL:
        assert canary not in text
        assert base64.b64encode(canary.encode()).decode() not in text
    assert str(machine.home) not in text
    assert canaries.USER not in text
    assert canaries.HOST not in text


@pytest.mark.parametrize("deep", [False, True])
def test_no_canary_reaches_any_rendered_output(tmp_path: Path, deep: bool) -> None:
    machine = _messy(tmp_path)
    snapshot = diagnose(
        inspect_all(machine.platform(), Policy(deep=deep, include_env=deep), machine.workspace)
    )
    assert snapshot.findings
    context = RedactionContext(str(machine.home), canaries.USER, canaries.HOST)
    redacted, counts = redacted_with_counts(snapshot, context)
    redacted = dataclasses.replace(redacted, redactions=counts)
    outputs = [render_json(redacted), render_markdown(redacted), render_sarif(redacted)]
    for render in (render_scan, render_agents, render_inventory):
        console = Console(record=True, width=200, color_system=None)
        render(redacted, console)
        outputs.append(console.export_text())
    for text in outputs:
        _assert_clean(text, machine)


def test_no_canary_reaches_the_command_line_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    machine = _messy(tmp_path)
    machine.workspace.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Platform, "current", classmethod(lambda cls: machine.platform()))
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext(str(machine.home), canaries.USER, canaries.HOST)),
    )
    workspace = str(machine.workspace)
    for args in (
        ("scan", "--workspace", workspace, "--all", "--deep", "--include-env"),
        ("scan", "--workspace", workspace, "-f", "json", "--deep", "--include-env"),
        ("scan", "--workspace", workspace, "-f", "sarif"),
        ("agents", "--workspace", workspace),
        ("inventory", "--workspace", workspace, "--deep", "--include-env"),
        ("report", "-o", "-", "-f", "markdown", "--workspace", workspace),
    ):
        run_main(monkeypatch, *args)
        captured = capsys.readouterr()
        _assert_clean(captured.out + captured.err, machine)
