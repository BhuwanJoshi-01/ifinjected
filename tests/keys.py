"""Private key *headers* for tests, built from the formats' specifications.

No real key is stored in this repository: an OpenSSH header is the magic string and the
cipher name, base64-encoded, followed by filler that carries the canary mark.
"""

from __future__ import annotations

import base64

from tests import canaries


def openssh(cipher: str = "none") -> str:
    kdf = "none" if cipher == "none" else "bcrypt"
    raw = b"openssh-key-v1\x00"
    for field in (cipher.encode(), kdf.encode()):
        raw += len(field).to_bytes(4, "big") + field
    raw += b"\x00" * 30
    body = base64.b64encode(raw).decode()
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{body}\n{canaries.SSH_KEY_BODY}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )


def pem_rsa(encrypted: bool = False) -> str:
    header = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n"
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + (header if encrypted else "")
        + f"MIIEow{canaries.MARK}IBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
    )


def pkcs8(encrypted: bool = False) -> str:
    label = "ENCRYPTED PRIVATE KEY" if encrypted else "PRIVATE KEY"
    return f"-----BEGIN {label}-----\nMIIE{canaries.MARK}vQIBADAN\n-----END {label}-----\n"


def putty(encryption: str = "none") -> str:
    return (
        "PuTTY-User-Key-File-3: ssh-ed25519\n"
        f"Encryption: {encryption}\n"
        "Comment: test\n"
        f"Public-Lines: 2\nAAAA{canaries.MARK}\n"
    )


PUBLIC_ED25519 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ5o3bbT6vD4v1x0T9eB8T3q2Jt9kmjXNmQxQ9s3yU0n"
    " alice@alice-mbp\n"
)
