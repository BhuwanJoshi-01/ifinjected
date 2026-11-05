"""Configuration files read as data, with the line each setting came from.

Agent settings are JSON, JSONC or TOML. Python's parsers give the values but not where
they were written; a finding that says *which line* to change is far more useful, and
SARIF needs it to annotate a pull request. These readers return the parsed document
together with a map from *key paths* to line numbers:

``("permissions", "deny", 2)`` is the third entry of ``permissions.deny``;
``("mcp_servers", "github", "command")`` a key in a TOML table.

The values come from :mod:`json` and :mod:`tomllib` (the reference parsers); the line
map is built by a separate scan, so a mistake in it can only cost a line number, never a
setting.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any

from ifinjected.parsers.jsonc import strip_jsonc

KeyPath = tuple[str | int, ...]


class ConfigSyntaxError(ValueError):
    """The file is not valid JSON, JSONC or TOML; the message says where."""


@dataclass(frozen=True, slots=True)
class Document:
    """A parsed configuration file and the line of each key path (1-based)."""

    data: Any
    lines: dict[KeyPath, int] = field(default_factory=dict)

    def line(self, *path: str | int) -> int | None:
        """The line of ``path``, or of its closest ancestor that has one."""
        key: KeyPath = tuple(path)
        while key:
            if key in self.lines:
                return self.lines[key]
            key = key[:-1]
        return None


def key_name(path: KeyPath) -> str:
    """``permissions.deny[2]`` for ``("permissions", "deny", 2)``."""
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + part
    return out


# --- JSON ---------------------------------------------------------------------------------


def parse_json(text: str, *, comments: bool = False) -> Document:
    """``text`` as JSON (or JSONC with ``comments``), with the line of every key path."""
    plain = strip_jsonc(text) if comments else text
    try:
        data = json.loads(plain)
    except json.JSONDecodeError as error:
        raise ConfigSyntaxError(f"is not valid JSON (line {error.lineno}: {error.msg})") from None
    lines: dict[KeyPath, int] = {}
    try:
        _JsonScanner(plain, lines).document()
    except _ScanError:
        lines = {}  # the values are right; only the line numbers are lost
    return Document(data, lines)


class _ScanError(Exception):
    pass


class _JsonScanner:
    """Walks valid JSON and records where each object key and array item starts."""

    def __init__(self, text: str, lines: dict[KeyPath, int]) -> None:
        self.text = text
        self.pos = 0
        self.line = 1
        self.lines = lines

    def document(self) -> None:
        self._ws()
        self._value(())

    def _advance(self, count: int = 1) -> None:
        chunk = self.text[self.pos : self.pos + count]
        self.line += chunk.count("\n")
        self.pos += count

    def _ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self._advance()

    def _peek(self) -> str:
        if self.pos >= len(self.text):
            raise _ScanError
        return self.text[self.pos]

    def _string(self) -> str:
        start = self.pos
        self._advance()  # opening quote
        while self._peek() != '"':
            self._advance(2 if self._peek() == "\\" else 1)
        self._advance()
        value: str = json.loads(self.text[start : self.pos])
        return value

    def _value(self, path: KeyPath) -> None:
        char = self._peek()
        if char == "{":
            self._object(path)
        elif char == "[":
            self._array(path)
        elif char == '"':
            self._string()
        else:
            match = re.compile(r"-?[0-9.eE+-]+|true|false|null").match(self.text, self.pos)
            if match is None:
                raise _ScanError
            self._advance(match.end() - self.pos)

    def _object(self, path: KeyPath) -> None:
        self._advance()
        self._ws()
        if self._peek() == "}":
            self._advance()
            return
        while True:
            self._ws()
            line = self.line
            key = self._string()
            self.lines.setdefault((*path, key), line)
            self._ws()
            if self._peek() != ":":
                raise _ScanError
            self._advance()
            self._ws()
            self._value((*path, key))
            self._ws()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "}":
                self._advance()
                return
            raise _ScanError

    def _array(self, path: KeyPath) -> None:
        self._advance()
        self._ws()
        if self._peek() == "]":
            self._advance()
            return
        index = 0
        while True:
            self._ws()
            self.lines.setdefault((*path, index), self.line)
            self._value((*path, index))
            index += 1
            self._ws()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "]":
                self._advance()
                return
            raise _ScanError


# --- TOML ---------------------------------------------------------------------------------

_TABLE = re.compile(r"^\s*(\[\[?)\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_KEY = re.compile(
    r"""^\s*((?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*'))*)\s*="""
)
_PART = re.compile(r"""[A-Za-z0-9_-]+|"[^"]*"|'[^']*'""")


def _toml_parts(dotted: str) -> list[str]:
    return [p.strip("\"'") for p in _PART.findall(dotted)]


def parse_toml(text: str) -> Document:
    """``text`` as TOML, with the line of every table and key."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigSyntaxError(f"is not valid TOML ({error})") from None
    lines: dict[KeyPath, int] = {}
    table: KeyPath = ()
    array_counts: dict[KeyPath, int] = {}
    in_multiline: str | None = None
    depth = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if in_multiline is not None:
            if raw.count(in_multiline) % 2 == 1:
                in_multiline = None
            continue
        if depth > 0:
            depth += raw.count("[") + raw.count("{") - raw.count("]") - raw.count("}")
            continue
        header = _TABLE.match(raw)
        if header is not None:
            parts: KeyPath = tuple(_toml_parts(header.group(2)))
            if header.group(1) == "[[":
                index = array_counts.get(parts, 0)
                array_counts[parts] = index + 1
                table = (*parts, index)
            else:
                table = parts
            lines.setdefault(table, number)
            continue
        key = _KEY.match(raw)
        if key is None:
            continue
        path = (*table, *_toml_parts(key.group(1)))
        lines.setdefault(path, number)
        rest = raw[key.end() :]
        for quote in ('"""', "'''"):
            if rest.count(quote) % 2 == 1:
                in_multiline = quote
        if in_multiline is None:
            depth = max(0, rest.count("[") + rest.count("{") - rest.count("]") - rest.count("}"))
    return Document(data, lines)
