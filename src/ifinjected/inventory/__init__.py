"""The inventory: sensitive items that exist on this machine, found without reading them."""

from __future__ import annotations

from collections.abc import Callable

from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.cloud import collect_cloud
from ifinjected.inventory.containers import collect_containers
from ifinjected.inventory.ssh import collect_ssh_keys
from ifinjected.inventory.tools import collect_tools
from ifinjected.inventory.vcs import collect_vcs

Collector = Callable[[Context], Collected]

COLLECTORS: tuple[Collector, ...] = (
    collect_ssh_keys,
    collect_cloud,
    collect_vcs,
    collect_containers,
    collect_tools,
)
"""Every collector, in report order."""


def collect_inventory(context: Context) -> Collected:
    found = Collected()
    for collector in COLLECTORS:
        found.extend(collector(context))
    return found
