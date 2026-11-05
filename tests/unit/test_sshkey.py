"""Telling a key and its protection from the first bytes of the file (IFJ-010)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from ifinjected.parsers.sshkey import (
    HEAD_BYTES,
    KeyFormat,
    KeyHeader,
    Protection,
    classify_private_key,
    parse_public_key,
)
from tests import keys


def _head(text: str) -> bytes:
    return text.encode()[:HEAD_BYTES]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (keys.openssh("none"), KeyHeader(KeyFormat.OPENSSH, Protection.NONE)),
        (keys.openssh("aes256-ctr"), KeyHeader(KeyFormat.OPENSSH, Protection.PASSPHRASE)),
        (
            keys.openssh("chacha20-poly1305@openssh.com"),
            KeyHeader(KeyFormat.OPENSSH, Protection.PASSPHRASE),
        ),
        (keys.pem_rsa(encrypted=False), KeyHeader(KeyFormat.PEM, Protection.NONE)),
        (keys.pem_rsa(encrypted=True), KeyHeader(KeyFormat.PEM, Protection.PASSPHRASE)),
        (keys.pkcs8(encrypted=False), KeyHeader(KeyFormat.PKCS8, Protection.NONE)),
        (keys.pkcs8(encrypted=True), KeyHeader(KeyFormat.PKCS8, Protection.PASSPHRASE)),
        (keys.putty("none"), KeyHeader(KeyFormat.PUTTY, Protection.NONE)),
        (keys.putty("aes256-cbc"), KeyHeader(KeyFormat.PUTTY, Protection.PASSPHRASE)),
    ],
)
def test_format_and_protection_from_the_head_alone(key: str, expected: KeyHeader) -> None:
    assert classify_private_key(_head(key)) == expected


def test_the_head_is_enough_for_an_openssh_key_with_a_long_cipher_name() -> None:
    head = _head(keys.openssh("chacha20-poly1305@openssh.com"))
    assert len(head) <= HEAD_BYTES
    assert classify_private_key(head) == KeyHeader(KeyFormat.OPENSSH, Protection.PASSPHRASE)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "Host github.com\n  IdentityFile ~/.ssh/id_ed25519\n",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
        keys.PUBLIC_ED25519,
    ],
)
def test_files_that_are_not_private_keys(text: str) -> None:
    assert classify_private_key(text.encode()) is None


@pytest.mark.parametrize(
    "body",
    [
        "not-base64!!\n",
        base64.b64encode(b"some-other-magic\x00\x00\x00\x00\x04none").decode() + "\n",
        base64.b64encode(b"openssh-key-v1\x00\x00\x00").decode() + "\n",
        base64.b64encode(b"openssh-key-v1\x00\x00\x00\x00\x00").decode() + "\n",
    ],
)
def test_an_unreadable_openssh_header_is_unknown_not_safe(body: str) -> None:
    head = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}".encode()
    assert classify_private_key(head) == KeyHeader(KeyFormat.OPENSSH, Protection.UNKNOWN)


def test_a_pem_header_cut_right_after_begin_is_unknown() -> None:
    head = b"-----BEGIN EC PRIVATE KEY-----\n"
    assert classify_private_key(head) == KeyHeader(KeyFormat.PEM, Protection.UNKNOWN)


def test_a_putty_key_without_an_encryption_line_is_unknown() -> None:
    assert classify_private_key(b"PuTTY-User-Key-File-2: ssh-rsa\n") == KeyHeader(
        KeyFormat.PUTTY, Protection.UNKNOWN
    )


def test_public_key_type_and_fingerprint_like_ssh_keygen() -> None:
    blob = keys.PUBLIC_ED25519.split()[1]
    expected = base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode()
    key = parse_public_key(keys.PUBLIC_ED25519)
    assert key is not None
    assert key.key_type == "ssh-ed25519"
    assert key.fingerprint == "SHA256:" + expected.rstrip("=")


def test_the_public_key_comment_is_not_kept() -> None:
    key = parse_public_key(keys.PUBLIC_ED25519)
    assert key is not None
    assert "alice" not in repr(key)


@pytest.mark.parametrize("text", ["", "# comment only\n", "ssh-ed25519 !!!notbase64\n", "one\n"])
def test_no_public_key(text: str) -> None:
    assert parse_public_key(text) is None
