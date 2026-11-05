"""Items that are known by their location alone: if the file is there, it holds a secret.

Most credential stores need nothing more than ``stat``: ``~/.config/gcloud/credentials.db``
exists or it does not. :func:`present` turns existing paths into items, with their
permission bits, and never opens anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from ifinjected.files import Kind, stat_entry
from ifinjected.inventory.base import Collected
from ifinjected.models import Evidence, SensitiveItem, Severity


def present(
    item_id: str,
    paths: Iterable[Path],
    *,
    title: str,
    severity: Severity,
    facts: tuple[Evidence, ...] = (),
    directories: bool = False,
) -> Collected:
    """An item for each of ``paths`` that is a regular file (or, with ``directories``, a
    non-empty-looking directory: one that exists)."""
    found = Collected()
    for path in dict.fromkeys(paths):
        info = stat_entry(path)
        wanted = Kind.DIRECTORY if directories else Kind.FILE
        if info.kind is not wanted:
            continue
        found.items.append(
            SensitiveItem(
                id=item_id,
                title=title,
                path=str(path),
                severity=severity,
                facts=facts,
                # A listable directory says nothing about the files in it.
                readable_by_others=None if directories else info.group_or_world_readable,
            )
        )
    return found
