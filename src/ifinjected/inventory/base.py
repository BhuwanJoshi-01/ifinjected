"""What every inventory collector returns, and the context it runs in."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ifinjected.homes import Platform
from ifinjected.inventory.catalog import Catalog, load_catalog
from ifinjected.models import Policy, SensitiveItem, SkippedFile


@dataclass(frozen=True, slots=True)
class Context:
    """The machine, the workspace (if any), the policy and the catalog a collector uses."""

    platform: Platform
    policy: Policy
    workspace: Path | None = None
    catalog: Catalog = field(default_factory=load_catalog)


@dataclass(slots=True)
class Collected:
    """Items found and files skipped by one collector."""

    items: list[SensitiveItem] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)

    def extend(self, other: Collected) -> None:
        self.items.extend(other.items)
        self.skipped.extend(other.skipped)
