"""One run, from the platform and the workspace to a snapshot the renderers can use.

Facts are collected here; the snapshot is redacted by the caller before it is shown.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected import __version__
from ifinjected.agents import inspect_agents
from ifinjected.homes import Platform
from ifinjected.inventory import collect_inventory
from ifinjected.inventory.base import Context
from ifinjected.models import Policy, Snapshot, utc_timestamp


def inspect_inventory(
    platform: Platform, policy: Policy, workspace: Path | None = None
) -> Snapshot:
    """Every sensitive item on the machine (and in the workspace and its parents)."""
    found = collect_inventory(Context(platform=platform, policy=policy, workspace=workspace))
    return Snapshot(
        tool_version=__version__,
        created_at=utc_timestamp(),
        system=platform.system.value,
        workspace=str(workspace) if workspace is not None else None,
        policy=policy,
        items=tuple(found.items),
        skipped=tuple(found.skipped),
    )


def inspect_agent_policies(
    platform: Platform, policy: Policy, workspace: Path | None = None
) -> Snapshot:
    """Every agent's configuration layers and effective policy for ``workspace``."""
    return Snapshot(
        tool_version=__version__,
        created_at=utc_timestamp(),
        system=platform.system.value,
        workspace=str(workspace) if workspace is not None else None,
        policy=policy,
        agents=inspect_agents(platform, policy, workspace),
    )
