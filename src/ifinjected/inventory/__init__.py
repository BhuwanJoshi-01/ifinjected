"""The inventory: sensitive items that exist on this machine, found without reading them."""

from __future__ import annotations

from collections.abc import Callable

from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.ssh import collect_ssh_keys

Collector = Callable[[Context], Collected]

COLLECTORS: tuple[Collector, ...] = (collect_ssh_keys,)
"""Every collector, in report order."""


def collect_inventory(context: Context) -> Collected:
    found = Collected()
    for collector in COLLECTORS:
        found.extend(collector(context))
    return found
