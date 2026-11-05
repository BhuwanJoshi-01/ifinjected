"""INI-style credential files (AWS credentials and config, .pypirc): structure only.

Only section names and the *names* of the keys in each section are kept; every value
is dropped as the line is read. That is enough to tell a profile with static access keys
from one that uses single sign-on, without the keys.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    keys: frozenset[str]


def ini_sections(text: str) -> tuple[Section, ...]:
    """Sections in order, each with the lower-cased names of its keys."""
    sections: list[Section] = []
    name: str | None = None
    keys: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if name is not None:
                sections.append(Section(name, frozenset(keys)))
            name, keys = line[1:-1].strip(), set()
            continue
        if name is None:
            continue
        for separator in ("=", ":"):
            if separator in line:
                key = line.split(separator, 1)[0].strip().lower()
                if key and " " not in key:
                    keys.add(key)
                break
        # Continuation lines and values are never kept.
    if name is not None:
        sections.append(Section(name, frozenset(keys)))
    return tuple(sections)
