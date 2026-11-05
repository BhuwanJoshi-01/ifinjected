"""SSH private keys in ``~/.ssh``: which exist, and whether a passphrase protects them.

The directory is listed by name. Files that are known not to be keys (``config``,
``known_hosts``, ``authorized_keys``, public keys) are left alone; every other regular
file gets a head read of the catalog's ``head_bytes``, which is enough to tell a key and
its protection and too little to contain the key itself in any usable form. The bytes
are classified and dropped by :mod:`ifinjected.parsers.sshkey`.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected.files import Kind, RefusedError, read_head, read_text, stat_entry
from ifinjected.files import list_directory as _list
from ifinjected.inventory.base import Collected, Context
from ifinjected.models import Evidence, SensitiveItem, Severity, SkippedFile
from ifinjected.parsers.sshkey import (
    MAX_PUBLIC_KEY_BYTES,
    Protection,
    classify_private_key,
    parse_public_key,
)

ITEM = "ssh.key"

_NOT_KEYS = frozenset({"config", "environment", "rc", "authorized_keys", "authorized_keys2"})
_NOT_KEY_PREFIXES = ("known_hosts", "config.", "authorized_keys")
_NOT_KEY_SUFFIXES = (".pub", ".sock", ".socket", ".old", "-cert.pub")

_SEVERITY = {
    Protection.NONE: Severity.HIGH,
    Protection.PASSPHRASE: Severity.MEDIUM,
    Protection.UNKNOWN: Severity.MEDIUM,
}
_PROTECTION_TEXT = {
    Protection.NONE: "no passphrase",
    Protection.PASSPHRASE: "passphrase",
    Protection.UNKNOWN: "protection unknown",
}


def _is_candidate(name: str) -> bool:
    if name.startswith(".") or name in _NOT_KEYS:
        return False
    return not name.startswith(_NOT_KEY_PREFIXES) and not name.endswith(_NOT_KEY_SUFFIXES)


def collect_ssh_keys(context: Context) -> Collected:
    entry = context.catalog.entry(ITEM)
    head_bytes = entry.head_bytes or 0
    directory = context.platform.home / ".ssh"
    found = Collected()
    names = _list(directory)
    if names is None:
        return found
    for name in names:
        if not _is_candidate(name):
            continue
        path = directory / name
        info = stat_entry(path)
        if info.kind is not Kind.FILE:
            continue
        try:
            head = read_head(path, head_bytes)
        except RefusedError as error:
            found.skipped.append(SkippedFile(str(path), str(error)))
            continue
        header = classify_private_key(head) if head else None
        del head
        if header is None:
            continue
        facts = [
            Evidence("ssh", "format", header.format.value),
            Evidence("ssh", "protection", header.protection.value),
        ]
        facts += _public_facts(path.with_name(name + ".pub"), found)
        found.items.append(
            SensitiveItem(
                id=ITEM,
                title=f"SSH private key ({_PROTECTION_TEXT[header.protection]})",
                path=str(path),
                severity=_SEVERITY[header.protection],
                facts=tuple(facts),
                readable_by_others=info.group_or_world_readable,
            )
        )
    return found


def _public_facts(public: Path, found: Collected) -> list[Evidence]:
    """Type and fingerprint from the matching public key, which is public."""
    try:
        text = read_text(public, MAX_PUBLIC_KEY_BYTES)
    except RefusedError as error:
        found.skipped.append(SkippedFile(str(public), str(error)))
        return []
    if text is None:
        return []
    key = parse_public_key(text)
    if key is None:
        return []
    return [
        Evidence("ssh", "key_type", key.key_type),
        Evidence("ssh", "fingerprint", key.fingerprint),
    ]
