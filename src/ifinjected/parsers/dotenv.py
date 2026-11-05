"""``.env`` files read as data, in the line format the common loaders agree on.

python-dotenv, Node's dotenv (and so Vite) and Docker Compose all accept ``KEY=value``,
an ``export`` prefix, spaces around ``=``, ``#`` comments, single, double and backtick
quotes, and quoted values over several lines. Other lines are ignored, as they are.

Nothing is expanded or run. ifinjected only ever keeps the *names*
(:func:`dotenv_names`): values exist for the duration of the parse and are never part of
any result. An
unquoted ``#`` starts a comment only after a space or tab, as in python-dotenv and
Compose; Node's dotenv also cuts ``https://x/#a`` there, so such values are rare in
practice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_LINE = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*(.*)")
_REFERENCE = re.compile(r"\$(?:\{[A-Za-z_]|[A-Za-z_])")
_COMMENT = re.compile(r"[ \t]+#")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
_QUOTES = "'\"`"
MAX_VALUE_LINES = 200  # a quoted value longer than this is treated as never closed


@dataclass(frozen=True, slots=True)
class EnvEntry:
    """One variable; ``line`` is where it starts. The value never appears in repr()."""

    key: str
    value: str = field(repr=False)
    line: int
    reference: bool = False


def parse_dotenv(text: str) -> tuple[EnvEntry, ...]:
    """The variables of a ``.env`` file; a later definition replaces an earlier one."""
    lines = text.replace("\r\n", "\n").split("\n")
    entries: dict[str, EnvEntry] = {}
    index = 0
    while index < len(lines):
        number = index + 1
        match = _LINE.fullmatch(lines[index])
        index += 1
        if match is None:
            continue
        key, rest = match.groups()
        if rest[:1] and rest[0] in _QUOTES:
            quoted = _quoted(rest[0], rest[1:], lines, index)
            if quoted is None:  # never closed: skip this line only
                continue
            value, index = quoted
            reference = rest[0] != "'" and _REFERENCE.search(value) is not None
        else:
            comment = _COMMENT.search(rest)
            value = (rest[: comment.start()] if comment else rest).rstrip(" \t")
            reference = _REFERENCE.search(value) is not None
        entries[key] = EnvEntry(key, value, number, reference)
    return tuple(entries.values())


def _quoted(quote: str, first: str, lines: list[str], index: int) -> tuple[str, int] | None:
    """The value of a quoted assignment and the index of the line after it."""
    text = first
    for extra in range(MAX_VALUE_LINES):
        end = _closing(text, quote)
        if end is not None:
            body = text[:end]
            return (_unescape(body) if quote == '"' else body), index + extra
        if index + extra >= len(lines):
            return None
        text += "\n" + lines[index + extra]
    return None


def _closing(text: str, quote: str) -> int | None:
    position = 0
    while position < len(text):
        char = text[position]
        if char == "\\" and quote == '"':
            position += 2
            continue
        if char == quote:
            return position
        position += 1
    return None


def _unescape(body: str) -> str:
    return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m.group(1), m.group(0)), body, flags=re.S)


def dotenv_names(text: str) -> tuple[str, ...]:
    """The variable names of a ``.env`` file, in order; every value is dropped here."""
    return tuple(entry.key for entry in parse_dotenv(text))


_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")


def is_env_file(name: str) -> bool:
    """``.env``, ``.env.local``, ``.env.production``…, but not the templates that are
    meant to be committed (``.env.example``, ``.env.sample``, ``.env.template``)."""
    if name != ".env" and not name.startswith(".env."):
        return False
    return not name.endswith(_EXAMPLE_SUFFIXES)
