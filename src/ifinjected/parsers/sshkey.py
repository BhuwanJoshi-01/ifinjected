"""What the first bytes of a private key file say about it, and nothing more.

A key file is read up to :data:`HEAD_BYTES`: enough for the ``-----BEGIN …-----`` line
and the first line of the body, which in the OpenSSH format names the cipher (``none``
when the key has no passphrase). PEM keys say ``ENCRYPTED`` in their header; PuTTY keys
have an ``Encryption:`` line. The bytes are classified and dropped here: no caller ever
sees them.

Public key files (``*.pub``) are public; their key type and fingerprint identify which
key a finding is about without touching the private one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

HEAD_BYTES = 192
"""BEGIN line (≤ 40 bytes) plus the first 70-character line of an OpenSSH key body."""

MAX_PUBLIC_KEY_BYTES = 16 * 1024


class KeyFormat(StrEnum):
    OPENSSH = "openssh"
    PEM = "pem"
    PKCS8 = "pkcs8"
    PUTTY = "putty"


class Protection(StrEnum):
    """``none``: anyone who can read the file can use the key. ``passphrase``: the file
    alone is not enough. ``unknown``: the header could not tell."""

    NONE = "none"
    PASSPHRASE = "passphrase"  # noqa: S105 - a protection kind, not a password
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class KeyHeader:
    format: KeyFormat
    protection: Protection


_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----\r?\n")
_OPENSSH_MAGIC = b"openssh-key-v1\x00"


def classify_private_key(head: bytes) -> KeyHeader | None:
    """The format and protection of a private key from its first bytes, or ``None``
    when ``head`` does not start like a private key file."""
    start = head.lstrip()
    if start.startswith(b"PuTTY-User-Key-File-"):
        return KeyHeader(KeyFormat.PUTTY, _putty_protection(start))
    match = _BEGIN.match(start)
    if match is None:
        return None
    label = match.group(1).strip()
    body = start[match.end() :]
    if label == b"OPENSSH":
        return KeyHeader(KeyFormat.OPENSSH, _openssh_protection(body))
    if label == b"ENCRYPTED":
        return KeyHeader(KeyFormat.PKCS8, Protection.PASSPHRASE)
    if label == b"":
        return KeyHeader(KeyFormat.PKCS8, Protection.NONE)
    # Traditional PEM (RSA, EC, DSA): encrypted ones carry a Proc-Type header.
    if body.startswith(b"Proc-Type:"):
        encrypted = b"ENCRYPTED" in body.split(b"\n", 1)[0]
        return KeyHeader(KeyFormat.PEM, Protection.PASSPHRASE if encrypted else Protection.NONE)
    return KeyHeader(KeyFormat.PEM, Protection.NONE if body else Protection.UNKNOWN)


def _openssh_protection(body: bytes) -> Protection:
    line = body.split(b"\n", 1)[0].strip()
    usable = len(line) // 4 * 4
    try:
        raw = base64.b64decode(line[:usable], validate=True)
    except (binascii.Error, ValueError):
        return Protection.UNKNOWN
    if not raw.startswith(_OPENSSH_MAGIC):
        return Protection.UNKNOWN
    rest = raw[len(_OPENSSH_MAGIC) :]
    if len(rest) < 4:
        return Protection.UNKNOWN
    length = int.from_bytes(rest[:4], "big")
    cipher = rest[4 : 4 + length]
    if len(cipher) != length or not length:
        return Protection.UNKNOWN
    return Protection.NONE if cipher == b"none" else Protection.PASSPHRASE


def _putty_protection(head: bytes) -> Protection:
    for line in head.splitlines()[1:4]:
        if line.startswith(b"Encryption:"):
            value = line.split(b":", 1)[1].strip()
            return Protection.NONE if value == b"none" else Protection.PASSPHRASE
    return Protection.UNKNOWN


@dataclass(frozen=True, slots=True)
class PublicKey:
    """A public key's type (``ssh-ed25519``) and SHA-256 fingerprint, as ``ssh-keygen -l``
    shows it. The comment (often ``user@host``) is not kept."""

    key_type: str
    fingerprint: str


def parse_public_key(text: str) -> PublicKey | None:
    """The first key in an OpenSSH ``.pub`` file, or ``None`` when there is none."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or line.lstrip().startswith("#"):
            continue
        key_type, blob = fields[0], fields[1]
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        return PublicKey(key_type=key_type, fingerprint=f"SHA256:{digest}")
    return None
