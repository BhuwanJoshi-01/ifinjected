"""Path patterns as agents write them, matched against absolute paths.

Adapters translate each agent's syntax (Claude Code's gitignore-style rules, Codex's
filesystem tokens, opencode's globs) into absolute patterns of one shape:

* ``*`` matches within one path segment, ``?`` one character, ``[…]`` a set;
* ``**`` as a whole segment matches any number of segments, including none;
* a pattern that names a directory also matches everything inside it, as gitignore
  does: ``/home/a/.ssh`` covers ``/home/a/.ssh/id_ed25519``.

Matching is case-sensitive, except for Windows paths, which are compared without case.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import PurePosixPath, PureWindowsPath


def _segments(path: str) -> tuple[list[str], bool]:
    """The segments of an absolute path and whether it is a Windows path."""
    windows = bool(re.match(r"^[A-Za-z]:[\\/]", path)) or path.startswith("\\\\")
    pure = PureWindowsPath(path) if windows else PurePosixPath(path)
    parts = list(pure.parts)
    if windows and parts:
        parts[0] = parts[0].rstrip("\\/").lower()
    return parts, windows


@lru_cache(maxsize=4096)
def _segment_regex(segment: str, ignore_case: bool) -> re.Pattern[str]:
    out = []
    index = 0
    while index < len(segment):
        char = segment[index]
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = segment.find("]", index + 1)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = segment[index + 1 : end]
                negate = body.startswith("!")
                body = body[1:] if negate else body
                body = body.replace("\\", "\\\\").replace("[", "\\[").replace("^", "\\^")
                out.append(("[^" if negate else "[") + body + "]")
                index = end
        else:
            out.append(re.escape(char))
        index += 1
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("".join(out) + r"\Z", flags)


def _match_segments(pattern: list[str], path: list[str], ignore_case: bool) -> bool:
    if not pattern:
        return True  # the pattern named an ancestor of the path: everything inside matches
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match_segments(rest, path[skip:], ignore_case) for skip in range(len(path) + 1))
    if not path:
        return False
    if not _segment_regex(head, ignore_case).match(path[0]):
        return False
    return _match_segments(rest, path[1:], ignore_case)


ANYWHERE = "**"
"""The pattern that covers every path on every system (a bare ``Read`` rule)."""


def matches(pattern: str, path: str) -> bool:
    """Whether absolute ``path`` is covered by absolute ``pattern``."""
    if pattern == ANYWHERE:
        return True
    pattern_parts, pattern_windows = _segments(pattern)
    path_parts, path_windows = _segments(path)
    if pattern_windows != path_windows:
        return False
    if not pattern_parts or not path_parts:
        return False
    ignore_case = path_windows
    first_pattern = pattern_parts[0].lower() if ignore_case else pattern_parts[0]
    first_path = path_parts[0].lower() if ignore_case else path_parts[0]
    if first_pattern != first_path:
        return False
    return _match_segments(pattern_parts[1:], path_parts[1:], ignore_case)


def inside(directory: str, path: str) -> bool:
    """Whether ``path`` is ``directory`` or anywhere below it (no wildcards)."""
    return matches(_escape(directory), path)


def _escape(literal: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", literal)
