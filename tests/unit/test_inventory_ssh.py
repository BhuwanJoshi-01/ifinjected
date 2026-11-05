"""SSH private keys in ~/.ssh, found by header without reading the key (IFJ-010)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ifinjected.files import Level, recording
from ifinjected.inventory.base import Context
from ifinjected.inventory.catalog import load_catalog
from ifinjected.inventory.ssh import collect_ssh_keys
from ifinjected.models import Policy, Severity
from tests import canaries, keys
from tests.homes import FakeMachine


def _collect(machine: FakeMachine) -> list[tuple[str, str | None, Severity]]:
    found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    return [(Path(i.path).name, i.fact("protection"), i.severity) for i in found.items]


def test_no_ssh_directory_means_no_keys(tmp_path: Path) -> None:
    assert _collect(FakeMachine(tmp_path)) == []


def test_keys_are_told_apart_by_their_protection(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".ssh/id_ed25519", keys.openssh("none"))
    machine.write(".ssh/work", keys.openssh("aes256-ctr"))
    machine.write(".ssh/legacy.pem", keys.pem_rsa(encrypted=False))
    assert _collect(machine) == [
        ("id_ed25519", "none", Severity.HIGH),
        ("legacy.pem", "none", Severity.HIGH),
        ("work", "passphrase", Severity.MEDIUM),
    ]


def test_files_that_are_not_keys_are_never_opened(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    for name in ("config", "known_hosts", "known_hosts.old", "authorized_keys", "id_ed25519.pub"):
        machine.write(f".ssh/{name}", "x")
    machine.write(".ssh/notes.txt", "just text")
    with recording() as ledger:
        assert _collect(machine) == []
    opened = {Path(a.path).name for a in ledger.accesses if a.level is not Level.STAT}
    assert opened == {"notes.txt"}  # an unknown file gets a head read, nothing more


def test_the_public_key_names_the_private_one(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".ssh/id_ed25519", keys.openssh("none"))
    machine.write(".ssh/id_ed25519.pub", keys.PUBLIC_ED25519)
    found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    item = found.items[0]
    assert item.fact("key_type") == "ssh-ed25519"
    assert (item.fact("fingerprint") or "").startswith("SHA256:")
    assert item.title == "SSH private key (no passphrase)"


def test_only_the_head_of_a_key_is_read_and_nothing_of_it_is_kept(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".ssh/id_ed25519", keys.openssh("none") + "A" * 100_000)
    head_bytes = load_catalog().entry("ssh.key").head_bytes
    with recording() as ledger:
        found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    reads = [a for a in ledger.accesses if a.path.endswith("id_ed25519")]
    assert [(a.level, a.bytes_read) for a in reads if a.level is Level.HEAD] == [
        (Level.HEAD, head_bytes)
    ]
    assert canaries.MARK not in repr(found)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_a_key_readable_by_other_users_says_so(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    key = machine.write(".ssh/id_rsa", keys.openssh("none"))
    key.chmod(0o644)
    found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    assert found.items[0].readable_by_others is True
    key.chmod(0o600)
    found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    assert found.items[0].readable_by_others is False


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs a non-root POSIX user"
)
def test_an_unreadable_key_is_reported_as_skipped(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    key = machine.write(".ssh/id_rsa", keys.openssh("none"))
    key.chmod(0)
    try:
        found = collect_ssh_keys(Context(platform=machine.platform(), policy=Policy()))
    finally:
        key.chmod(0o600)
    assert found.items == []
    assert [Path(s.path).name for s in found.skipped] == ["id_rsa"]


def test_a_directory_named_like_a_key_is_ignored(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    (machine.home / ".ssh" / "id_old").mkdir(parents=True)
    assert _collect(machine) == []
