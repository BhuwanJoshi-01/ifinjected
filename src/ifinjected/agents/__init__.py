"""Agent adapters: each agent's configuration read as data, reduced to one shape."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ifinjected.agents.base import AgentReport
from ifinjected.agents.claude_code import inspect_claude_code
from ifinjected.agents.codex import inspect_codex
from ifinjected.agents.copilot import inspect_copilot
from ifinjected.agents.cursor import inspect_cursor
from ifinjected.agents.gemini import inspect_gemini
from ifinjected.agents.opencode import inspect_opencode
from ifinjected.homes import Platform
from ifinjected.models import AgentId, Policy

Adapter = Callable[[Platform, Policy, Path | None], AgentReport]

ADAPTERS: dict[AgentId, Adapter] = {
    AgentId.CLAUDE_CODE: inspect_claude_code,
    AgentId.CODEX: inspect_codex,
    AgentId.GEMINI_CLI: inspect_gemini,
    AgentId.CURSOR: inspect_cursor,
    AgentId.OPENCODE: inspect_opencode,
    AgentId.COPILOT_CLI: inspect_copilot,
}
"""Adapters by agent; agents without one yet are reported as not inspected."""


def inspect_agents(
    platform: Platform, policy: Policy, workspace: Path | None
) -> tuple[AgentReport, ...]:
    """A report for every agent the policy asks for (all agents with an adapter by
    default) that leaves a trace on this machine."""
    wanted = policy.agents or tuple(ADAPTERS)
    reports = []
    for agent in wanted:
        adapter = ADAPTERS.get(agent)
        if adapter is None:
            continue
        report = adapter(platform, policy, workspace)
        if report.found or policy.agents:
            reports.append(report)
    return tuple(reports)
