"""The three levels of looking at a file, and the ledger that records every look."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ifinjected import files
from ifinjected.files import (
    Kind,
    Level,
    RefusedError,
    read_file,
    read_head,
    read_inside,
    read_text,
    read_text_inside,
    recording,
    stat_entry,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions and FIFOs")


def _link(link: Path, target: str | Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available")


# --- stat ---------------------------------------------------------------------------------


def test_stat_of_a_missing_path(tmp_path: Path) -> None:
    entry = stat_entry(tmp_path / "nope")
    assert entry.kind is Kind.MISSING
    assert not entry.exists


def test_stat_of_a_file_never_opens_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = tmp_path / "id_ed25519"
    key.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")

    def no_open(*args: object, **kwargs: object) -> int:
        raise AssertionError("stat_entry opened a file")

    monkeypatch.setattr(os, "open", no_open)
    entry = stat_entry(key)
    assert entry.kind is Kind.FILE
    assert entry.size == key.stat().st_size
    assert not entry.is_link


def test_stat_of_a_directory(tmp_path: Path) -> None:
    entry = stat_entry(tmp_path)
    assert entry.kind is Kind.DIRECTORY
    assert entry.size is None


def test_stat_follows_a_link_and_says_so(tmp_path: Path) -> None:
    (tmp_path / "real").write_bytes(b"x")
    _link(tmp_path / "alias", tmp_path / "real")
    entry = stat_entry(tmp_path / "alias")
    assert (entry.kind, entry.is_link, entry.dangling) == (Kind.FILE, True, False)


def test_stat_of_a_dangling_link(tmp_path: Path) -> None:
    _link(tmp_path / "alias", tmp_path / "gone")
    entry = stat_entry(tmp_path / "alias")
    assert (entry.kind, entry.is_link, entry.dangling) == (Kind.MISSING, True, True)


@posix_only
def test_stat_reports_permission_bits_and_readability(tmp_path: Path) -> None:
    private = tmp_path / "credentials"
    private.write_bytes(b"x")
    private.chmod(0o600)
    shared = tmp_path / "shared"
    shared.write_bytes(b"x")
    shared.chmod(0o644)
    assert stat_entry(private).mode == 0o600
    assert stat_entry(private).group_or_world_readable is False
    assert stat_entry(shared).group_or_world_readable is True
    assert stat_entry(private).uid == os.getuid()


@posix_only
def test_stat_of_a_fifo_is_other(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert stat_entry(fifo).kind is Kind.OTHER


# --- head ---------------------------------------------------------------------------------


def test_head_reads_at_most_n_bytes_of_a_large_file(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"A" * 1_000_000)
    with recording() as ledger:
        head = read_head(big, 4096)
    assert head == b"A" * 4096
    assert [(a.level, a.bytes_read) for a in ledger.accesses] == [(Level.HEAD, 4096)]


def test_head_of_a_short_file_is_the_whole_file(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"short")
    assert read_head(tmp_path / "f", 4096) == b"short"


def test_head_of_a_missing_file_is_none(tmp_path: Path) -> None:
    assert read_head(tmp_path / "nope", 10) is None


def test_head_refuses_a_directory(tmp_path: Path) -> None:
    with pytest.raises(RefusedError, match="not a regular file"):
        read_head(tmp_path, 10)


@posix_only
def test_head_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(RefusedError, match="not a regular file"):
        read_head(fifo, 10)


def test_head_needs_a_positive_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        read_head(tmp_path / "f", 0)


# --- full ---------------------------------------------------------------------------------


def test_a_whole_file_is_read(tmp_path: Path) -> None:
    (tmp_path / "settings.json").write_bytes(b'{"permissions": {}}')
    assert read_file(tmp_path / "settings.json", 100) == b'{"permissions": {}}'


def test_a_file_of_exactly_the_cap_is_read(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x" * 100)
    assert read_file(tmp_path / "f", 100) == b"x" * 100


def test_a_file_over_the_cap_is_refused_not_cut(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x" * 101)
    with recording() as ledger, pytest.raises(RefusedError, match="larger than 100 bytes"):
        read_file(tmp_path / "f", 100)
    assert ledger.accesses[0].bytes_read == 101  # one byte past the cap, never more


def test_a_configuration_link_into_a_dotfiles_repository_is_followed(tmp_path: Path) -> None:
    (tmp_path / "dotfiles").mkdir()
    (tmp_path / "dotfiles" / "settings.json").write_bytes(b"{}")
    (tmp_path / ".claude").mkdir()
    _link(tmp_path / ".claude" / "settings.json", tmp_path / "dotfiles" / "settings.json")
    assert read_file(tmp_path / ".claude" / "settings.json", 100) == b"{}"


def test_a_dangling_configuration_link_is_refused(tmp_path: Path) -> None:
    _link(tmp_path / "settings.json", tmp_path / "gone.json")
    with pytest.raises(RefusedError, match="does not exist"):
        read_file(tmp_path / "settings.json", 100)


def test_text_is_utf8_without_a_byte_order_mark(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes('﻿{"a": "é"}'.encode())
    assert read_text(tmp_path / "f", 100) == '{"a": "é"}'


def test_text_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(RefusedError, match="not UTF-8"):
        read_text(tmp_path / "f", 100)


# --- inside a workspace -------------------------------------------------------------------


def test_a_workspace_file_in_a_subdirectory(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_bytes(b"{}")
    assert read_inside(tmp_path, Path(".claude", "settings.json"), 100) == b"{}"


def test_a_missing_workspace_file_is_none(tmp_path: Path) -> None:
    assert read_inside(tmp_path, ".mcp.json", 100) is None


def test_a_link_within_the_workspace_is_followed(tmp_path: Path) -> None:
    (tmp_path / "shared.json").write_bytes(b"{}")
    _link(tmp_path / ".mcp.json", "shared.json")
    assert read_text_inside(tmp_path, ".mcp.json", 100) == "{}"


def test_a_link_out_of_the_workspace_is_refused(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (tmp_path / "elsewhere.json").write_bytes(b"{}")
    _link(workspace / ".mcp.json", tmp_path / "elsewhere.json")
    with pytest.raises(RefusedError, match="outside the workspace"):
        read_inside(workspace, ".mcp.json", 100)


def test_dot_dot_does_not_leave_the_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (tmp_path / "outside.json").write_bytes(b"x")
    with pytest.raises(RefusedError, match="outside the workspace"):
        read_inside(workspace, Path("..", "outside.json"), 100)


# --- the ledger ---------------------------------------------------------------------------


def test_the_ledger_records_every_level(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"12345")
    with recording() as ledger:
        stat_entry(tmp_path / "a")
        read_head(tmp_path / "a", 2)
        read_file(tmp_path / "a", 100)
        read_file(tmp_path / "missing", 100)
    assert [(Path(a.path).name, a.level, a.bytes_read) for a in ledger.accesses] == [
        ("a", Level.STAT, 0),
        ("a", Level.HEAD, 2),
        ("a", Level.FULL, 5),
        ("missing", Level.FULL, 0),
    ]
    assert ledger.paths(Level.HEAD) == {str(tmp_path / "a")}


def test_nothing_is_recorded_outside_a_recording(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x")
    read_file(tmp_path / "a", 10)
    assert files._LEDGER.get() is None


def test_recordings_nest_without_leaking(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x")
    with recording() as outer:
        with recording() as inner:
            read_file(tmp_path / "a", 10)
        stat_entry(tmp_path / "a")
    assert [a.level for a in inner.accesses] == [Level.FULL]
    assert [a.level for a in outer.accesses] == [Level.STAT]
