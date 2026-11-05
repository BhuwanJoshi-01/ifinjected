"""A digest of a directory tree, to prove a command wrote nothing."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def tree_digest(root: Path) -> str:
    """Names, sizes, modes and contents of everything under ``root``, as one hash."""
    digest = hashlib.sha256()
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames) + [f"{d}/" for d in dirnames]:
            path = Path(directory, name.rstrip("/"))
            info = path.lstat()
            digest.update(f"{path.relative_to(root)}|{info.st_size}|{info.st_mode}".encode())
            if path.is_file() and not path.is_symlink():
                digest.update(path.read_bytes())
    return digest.hexdigest()
