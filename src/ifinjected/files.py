"""The only ways ifinjected looks at a file, and a ledger of every look.

There are three levels, and each sensitive item in the catalog is assigned one:

* :func:`stat_entry` (``stat``): whether a path exists, what it is, its permission bits,
  size and owner. The file is never opened. This is all a credential file gets by default.
* :func:`read_head` (``head``): at most *n* bytes from the start of a regular file. An SSH
  key's first line says whether it is encrypted; nothing past it is read.
* :func:`read_file` (``full``): a whole configuration file, refused (never cut) above a
  size cap. Agent settings and MCP configuration are read like this, as data.

Workspace files go through :func:`read_inside`, which also refuses links that leave the
workspace. Only regular files are opened (a named pipe would block, a device could be
endless), and what was opened is checked again with ``fstat``.

Every look is recorded in the active :class:`ReadLedger` (see :func:`recording`). The
privacy contract tests run whole scans inside one and compare it with the catalog: a
path that is not declared, or more bytes than its level allows, fails the suite.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_INSIDE_FLAGS = _FLAGS | getattr(os, "O_NOFOLLOW", 0)


class RefusedError(Exception):
    """The file exists but was not read; ``str()`` completes "<path> …" for a report."""


class Level(StrEnum):
    """How deep a look goes: ``stat`` never opens the file, ``head`` reads a bounded
    prefix, ``full`` reads a whole (capped) configuration file."""

    STAT = "stat"
    HEAD = "head"
    FULL = "full"


@dataclass(frozen=True, slots=True)
class Access:
    """One look at one path: how deep, and how many bytes were actually read."""

    path: str
    level: Level
    bytes_read: int = 0


@dataclass(slots=True)
class ReadLedger:
    """Every :class:`Access` made while it was active, in order."""

    accesses: list[Access] = field(default_factory=list)

    def record(self, access: Access) -> None:
        self.accesses.append(access)

    def paths(self, level: Level | None = None) -> set[str]:
        """The paths looked at, at ``level`` or at any level."""
        return {a.path for a in self.accesses if level is None or a.level is level}


_LEDGER: ContextVar[ReadLedger | None] = ContextVar("ifinjected_read_ledger", default=None)


@contextmanager
def recording() -> Iterator[ReadLedger]:
    """Record every look made inside the ``with`` block in a fresh ledger."""
    ledger = ReadLedger()
    token = _LEDGER.set(ledger)
    try:
        yield ledger
    finally:
        _LEDGER.reset(token)


def _record(path: Path, level: Level, bytes_read: int = 0) -> None:
    ledger = _LEDGER.get()
    if ledger is not None:
        ledger.record(Access(str(path), level, bytes_read))


class Kind(StrEnum):
    MISSING = "missing"
    FILE = "file"
    DIRECTORY = "directory"
    OTHER = "other"
    """A socket, a pipe or a device."""


@dataclass(frozen=True, slots=True)
class Entry:
    """What ``stat`` says about a path, without opening it.

    ``kind`` describes what the path leads to (links are followed, as an agent would);
    ``is_link`` says whether the path itself is a symbolic link and ``dangling`` whether
    that link points nowhere. ``mode`` holds the permission bits only (``0o600``).
    ``uid`` is ``None`` on Windows.
    """

    path: str
    kind: Kind
    is_link: bool = False
    dangling: bool = False
    mode: int | None = None
    size: int | None = None
    uid: int | None = None

    @property
    def exists(self) -> bool:
        return self.kind is not Kind.MISSING

    @property
    def group_or_world_readable(self) -> bool | None:
        """``None`` where permission bits mean nothing (Windows) or are unknown."""
        if self.mode is None or os.name == "nt":
            return None
        return bool(self.mode & (stat.S_IRGRP | stat.S_IROTH))


def stat_entry(path: Path) -> Entry:
    """What ``path`` is, from ``lstat`` and ``stat`` only. Never opens anything."""
    _record(path, Level.STAT)
    try:
        link_info = path.lstat()
    except OSError:
        return Entry(str(path), Kind.MISSING)
    is_link = stat.S_ISLNK(link_info.st_mode)
    try:
        info = path.stat() if is_link else link_info
    except OSError:
        return Entry(str(path), Kind.MISSING, is_link=True, dangling=True)
    if stat.S_ISREG(info.st_mode):
        kind = Kind.FILE
    elif stat.S_ISDIR(info.st_mode):
        kind = Kind.DIRECTORY
    else:
        kind = Kind.OTHER
    return Entry(
        str(path),
        kind,
        is_link=is_link,
        mode=stat.S_IMODE(info.st_mode),
        size=info.st_size if kind is Kind.FILE else None,
        uid=getattr(info, "st_uid", None) if os.name != "nt" else None,
    )


def _open_regular(path: Path, flags: int = _FLAGS) -> int:
    """A file descriptor for the regular file at ``path``, or :class:`RefusedError`."""
    try:
        if not stat.S_ISREG(path.stat().st_mode):  # Windows cannot open() a directory
            raise RefusedError("is not a regular file")
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise RefusedError("could not be read (a link to a file that does not exist)") from None
    except OSError as error:
        raise RefusedError(f"could not be read ({error.strerror or error})") from None
    try:
        # Checked again on what was opened: a file swapped for a pipe after the check
        # cannot block (O_NONBLOCK) and is refused here.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RefusedError("is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_up_to(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        while size < limit and (chunk := os.read(fd, limit - size)):
            chunks.append(chunk)
            size += len(chunk)
    except OSError as error:
        raise RefusedError(f"could not be read ({error.strerror or error})") from None
    return b"".join(chunks)


def read_head(path: Path, max_bytes: int) -> bytes | None:
    """At most the first ``max_bytes`` bytes of ``path``; ``None`` when it does not exist.

    Never reads past ``max_bytes``, whatever the file's size. Raises
    :class:`RefusedError` when the path is not a regular file or cannot be read.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not os.path.lexists(path):
        _record(path, Level.HEAD)
        return None
    fd = _open_regular(path)
    data = b""
    try:
        data = _read_up_to(fd, max_bytes)
    finally:
        os.close(fd)
        _record(path, Level.HEAD, len(data))
    return data


def read_file(path: Path, max_bytes: int) -> bytes | None:
    """The whole of ``path``, or ``None`` when it does not exist.

    For configuration files, which may live anywhere (home, system and managed
    directories) and may be links into a dotfiles repository; links are followed, as
    the agent follows them. Raises :class:`RefusedError` when the path is not a regular
    file, cannot be read, or is larger than ``max_bytes`` (it is refused, not cut: half
    a configuration file can mean something else).
    """
    if not os.path.lexists(path):
        _record(path, Level.FULL)
        return None
    fd = _open_regular(path)
    data = b""
    try:
        data = _read_up_to(fd, max_bytes + 1)
    finally:
        os.close(fd)
        _record(path, Level.FULL, len(data))
    if len(data) > max_bytes:
        raise RefusedError(f"is larger than {max_bytes} bytes")
    return data


def read_inside(root: Path, relative: str | Path, max_bytes: int) -> bytes | None:
    """The bytes of ``root / relative``, or ``None`` when there is no such file.

    For files of the workspace being scanned: links may point elsewhere inside
    ``root`` but not out of it. Raises :class:`RefusedError` like :func:`read_file`, and
    for a link out of ``root``.
    """
    path = root / relative
    if not os.path.lexists(path):
        _record(path, Level.FULL)
        return None
    try:
        target = path.resolve(strict=True)
    except FileNotFoundError:
        _record(path, Level.STAT)
        raise RefusedError("could not be read (a link to a file that does not exist)") from None
    except OSError as error:
        _record(path, Level.STAT)
        raise RefusedError(f"could not be read ({error.strerror or error})") from None
    if not target.is_relative_to(root.resolve(strict=True)):
        _record(path, Level.STAT)
        raise RefusedError("is a link to a file outside the workspace")
    return read_file(target, max_bytes)


def decode_text(raw: bytes) -> str:
    """``raw`` as UTF-8 text (a byte order mark is dropped), or :class:`RefusedError`."""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise RefusedError("is not UTF-8 text") from None


def read_text(path: Path, max_bytes: int) -> str | None:
    """Like :func:`read_file`, decoded as UTF-8."""
    raw = read_file(path, max_bytes)
    return None if raw is None else decode_text(raw)


def read_text_inside(root: Path, relative: str | Path, max_bytes: int) -> str | None:
    """Like :func:`read_inside`, decoded as UTF-8."""
    raw = read_inside(root, relative, max_bytes)
    return None if raw is None else decode_text(raw)
