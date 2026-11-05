"""Items that are known by their location alone: if the file is there, it holds a secret.

Most credential stores need nothing more than ``stat``: ``~/.config/gcloud/credentials.db``
exists or it does not. :func:`present` turns existing paths into items, with their
permission bits, and never opens anything.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path

from ifinjected.files import Kind, RefusedError, read_text, stat_entry
from ifinjected.inventory.base import Collected, Context
from ifinjected.models import Evidence, SensitiveItem, Severity, SkippedFile


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


Refinement = tuple[str, Severity, tuple[Evidence, ...]]
"""A better title, severity and facts, learned from a file's structure."""


def refined(
    context: Context,
    found: Collected,
    item: SensitiveItem,
    analyse: Callable[[str], Refinement | None],
) -> SensitiveItem:
    """``item`` improved by reading its file for structure, when ``--deep`` asks for it.

    The text goes to ``analyse`` and nowhere else; what comes back are names and kinds.
    Without ``--deep``, or when the file cannot be read or understood, ``item`` is
    returned as it is (and an unreadable file is noted as skipped).
    """
    if not context.policy.deep:
        return item
    path = Path(item.path)
    try:
        text = read_text(path, context.policy.max_file_bytes)
    except RefusedError as error:
        found.skipped.append(SkippedFile(str(path), str(error)))
        return item
    result = analyse(text or "")
    del text
    if result is None:
        return item
    title, severity, facts = result
    return replace(item, title=title, severity=severity, facts=item.facts + facts)


def each(
    context: Context,
    item_id: str,
    paths: Iterable[Path],
    *,
    title: str,
    severity: Severity,
    analyse: Callable[[str], Refinement | None] | None = None,
) -> Collected:
    """:func:`present`, then :func:`refined` for every item found."""
    found = present(item_id, paths, title=title, severity=severity)
    if analyse is not None:
        found.items = [refined(context, found, item, analyse) for item in found.items]
    return found
