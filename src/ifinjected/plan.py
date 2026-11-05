"""``ifinjected plan``: the configuration change that closes each agent's exposures.

Suggestions only: nothing is ever applied. For every agent with reachable credentials,
the directories that hold them are collected (``~/.ssh``, ``~/.aws``…), and the
agent-specific way to deny them at the operating-system level is written out as a
snippet for the right file, with the other changes that close the trifecta: removing
interpreter allow rules, turning off modes that skip approvals, keeping secret-named
variables out of commands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePath

from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import AgentId, Snapshot
from ifinjected.policy.model import Channel

_SOCKETS = {"socket.ssh_agent", "socket.docker", "socket.gpg_agent"}


@dataclass(frozen=True, slots=True)
class Step:
    """One change: which file, the snippet to merge into it, and why."""

    agent: AgentId
    file: str
    snippet: str
    why: str


def _directories(snapshot: Snapshot, agent: AgentId, home: str | None) -> list[tuple[str, bool]]:
    """(path, is a directory) for the credentials ``agent`` can reach, one level below
    home where possible (``~/.ssh`` rather than ``~/.ssh/id_ed25519``; two below
    ``~/.config`` and three below ``~/.local``)."""
    found: dict[str, bool] = {}
    for exposure in snapshot.exposures:
        if exposure.agent is not agent or not exposure.reach.reachable:
            continue
        if exposure.path == ENVIRONMENT or exposure.item in _SOCKETS or exposure.item == "env.file":
            continue
        path = PurePath(exposure.path)
        target, directory = str(path), False
        if home is not None:
            try:
                parts = path.relative_to(home).parts
            except ValueError:
                parts = ()
            depth = {".config": 2, ".local": 3}.get(parts[0], 1) if parts else 0
            if parts and len(parts) > depth:
                target, directory = str(PurePath(home, *parts[:depth])), True
        found[target] = found.get(target, False) or directory
    return sorted(found.items())


def _tilde(path: str, home: str | None) -> str:
    if home and (path == home or path.startswith(home.rstrip("/\\") + "/")):
        return "~" + path[len(home.rstrip("/\\")) :]
    return path


def _env_reachable(snapshot: Snapshot, agent: AgentId) -> bool:
    return any(
        e.agent is agent and e.path == ENVIRONMENT and e.reach.reachable for e in snapshot.exposures
    )


def make_plan(snapshot: Snapshot, home: str | None) -> tuple[Step, ...]:
    steps: list[Step] = []
    for report in snapshot.agents:
        if not report.found or report.policy is None:
            continue
        agent = report.agent
        targets = [(_tilde(d, home), is_dir) for d, is_dir in _directories(snapshot, agent, home)]
        dirs = [d for d, _ in targets]
        env = _env_reachable(snapshot, agent)
        interpreter_rules = [
            c.source
            for c in report.policy.channels
            if c.channel is Channel.SHELL_ARBITRARY and c.source is not None
        ]
        if agent is AgentId.CLAUDE_CODE:
            if dirs or env:
                sandbox: dict[str, object] = {"enabled": True, "allowUnsandboxedCommands": False}
                if dirs:
                    sandbox["filesystem"] = {"denyRead": dirs}
                settings: dict[str, object] = {"sandbox": sandbox}
                if dirs:
                    settings["permissions"] = {
                        "deny": [
                            f"Read({d}/**)" if is_dir else f"Read({d})" for d, is_dir in targets
                        ]
                    }
                why = (
                    "The sandbox refuses these paths to every command, and the Read rules cover "
                    "the file tools, which run outside it."
                )
                if env:
                    why += (
                        " Start the agent from a shell without secret variables: every command "
                        "inherits them."
                    )
                steps.append(
                    Step(agent, "~/.claude/settings.json", json.dumps(settings, indent=2), why)
                )
            if report.mode == "bypassPermissions":
                steps.append(
                    Step(
                        agent,
                        "~/.claude/settings.json",
                        json.dumps(
                            {
                                "permissions": {
                                    "defaultMode": "default",
                                    "disableBypassPermissionsMode": "disable",
                                }
                            },
                            indent=2,
                        ),
                        "Bring back permission prompts.",
                    )
                )
            for source in interpreter_rules:
                steps.append(
                    Step(
                        agent,
                        f"{source.path}:{source.line}",
                        "remove this allow rule",
                        "It lets a script read any file without a prompt, around every Read rule.",
                    )
                )
        elif agent is AgentId.CODEX:
            if dirs or env:
                lines = [
                    'default_permissions = "ifinjected"',
                    "",
                    "[permissions.ifinjected.filesystem]",
                    '":workspace_roots" = "write"',
                ]
                lines += [f'"{d}" = "deny"' for d in dirs]
                if env:
                    lines += ["", "[shell_environment_policy]", "ignore_default_excludes = false"]
                steps.append(
                    Step(
                        agent,
                        "~/.codex/config.toml",
                        "\n".join(lines),
                        "Codex's sandbox reads the whole disk unless a permissions profile denies "
                        "paths.",
                    )
                )
            if report.mode and report.mode.startswith("danger-full-access"):
                steps.append(
                    Step(
                        agent,
                        "~/.codex/config.toml",
                        'sandbox_mode = "workspace-write"\napproval_policy = "on-request"',
                        "Run commands in the sandbox again, and ask before leaving it.",
                    )
                )
        elif agent is AgentId.GEMINI_CLI and dirs:
            steps.append(
                Step(
                    agent,
                    "~/.gemini/settings.json",
                    json.dumps({"tools": {"sandbox": "docker"}}, indent=2),
                    "A container sandbox sees only the workspace; the default macOS profile reads "
                    "everything.",
                )
            )
        elif agent is AgentId.OPENCODE:
            steps.append(
                Step(
                    agent,
                    "~/.config/opencode/opencode.json",
                    json.dumps(
                        {
                            "permission": {
                                "bash": "ask",
                                "webfetch": "ask",
                                "external_directory": "ask",
                            }
                        },
                        indent=2,
                    ),
                    "opencode has no sandbox and allows bash and web fetches by default.",
                )
            )
        elif agent is AgentId.CURSOR and dirs:
            steps.append(
                Step(
                    agent,
                    "~/.cursor/sandbox.json",
                    json.dumps({"readBoundary": "workspace"}, indent=2),
                    "Make reads outside the workspace ask, and keep the sandbox to the workspace.",
                )
            )
        elif agent is AgentId.COPILOT_CLI and (dirs or env):
            steps.append(
                Step(
                    agent,
                    "~/.copilot/settings.json",
                    json.dumps(
                        {
                            "sandbox": {
                                "enabled": True,
                                "allowBypass": False,
                                "auth": {"git": False, "gh": False},
                                "userPolicy": {"filesystem": {"deniedPaths": dirs}},
                            }
                        },
                        indent=2,
                    ),
                    "Run commands in the sandbox, without your git and gh credentials, away from "
                    "these paths.",
                )
            )
    return tuple(steps)


def render_plan_text(steps: tuple[Step, ...]) -> str:
    if not steps:
        return "Nothing to change: no agent can reach a credential.\n"
    out = ["Suggested changes (nothing was applied). Merge each snippet into the file named.", ""]
    current: AgentId | None = None
    for step in steps:
        if step.agent is not current:
            out.append(step.agent.display_name)
            current = step.agent
        out.append(f"  {step.file}")
        out.append(f"  {step.why}")
        out += ["    " + line for line in step.snippet.splitlines()]
        out.append("")
    out.append("Check the result with: ifinjected scan")
    return "\n".join(out) + "\n"


def render_plan_json(steps: tuple[Step, ...]) -> str:
    return (
        json.dumps(
            [
                {"agent": s.agent.value, "file": s.file, "snippet": s.snippet, "why": s.why}
                for s in steps
            ],
            indent=2,
        )
        + "\n"
    )
