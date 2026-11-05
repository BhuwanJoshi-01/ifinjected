"""Helpers the rule modules share: lookups over a snapshot and wording."""

from __future__ import annotations

from collections.abc import Iterator

from ifinjected.agents.base import AgentReport
from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import AgentId, Evidence, SensitiveItem, Snapshot, SourceRef
from ifinjected.policy.exposure import Exposure
from ifinjected.policy.model import Channel, Gate

CHANNEL_WORDS = {
    Channel.FILE_TOOL: "its file tools",
    Channel.SHELL_RECOGNIZED: "a read-only command such as cat",
    Channel.SHELL_ARBITRARY: "a command that opens the file itself (a Python or Node one-liner)",
    Channel.MCP: "an MCP server",
    Channel.HOOK: "a hook",
}
GATE_WORDS = {
    Gate.NONE: "without anyone's approval",
    Gate.AUTOMATED: "once a classifier approves",
    Gate.HUMAN: "once you approve",
    Gate.DENIED: "never",
}


def agents_found(snapshot: Snapshot) -> Iterator[AgentReport]:
    return (a for a in snapshot.agents if a.found and a.policy is not None)


def item_of(snapshot: Snapshot, exposure: Exposure) -> SensitiveItem | None:
    return next(
        (i for i in snapshot.items if i.id == exposure.item and i.path == exposure.path), None
    )


def exposures_of(snapshot: Snapshot, agent: AgentId) -> list[Exposure]:
    return [e for e in snapshot.exposures if e.agent is agent]


def item_source(item: SensitiveItem) -> tuple[SourceRef, ...]:
    return () if item.path == ENVIRONMENT else (SourceRef(item.path),)


def item_evidence(item: SensitiveItem) -> tuple[Evidence, ...]:
    return (Evidence("inventory", "item", item.id), *item.facts)


def how(exposure: Exposure) -> str:
    """'through a read-only command such as cat, without anyone's approval'."""
    if exposure.channel is None or exposure.gate is None:
        return "in a way that could not be decided"
    channel = CHANNEL_WORDS[exposure.channel]
    if exposure.path == ENVIRONMENT:
        channel = "a shell command such as env or echo"
    sandbox = " inside the sandbox" if exposure.sandboxed else ""
    return f"through {channel}{sandbox}, {GATE_WORDS[exposure.gate]}"
