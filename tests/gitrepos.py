"""Real git repositories in temporary directories, isolated from the user's git config."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed git commands in tests
        ["git", "-C", str(repo), *args],  # noqa: S607
        env=_ENV,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    return path


def commit(
    repo: Path, files: dict[str, str | dict[str, Any] | None], message: str = "change"
) -> str:
    """Write (or, for None, delete) files and commit them; returns the commit id."""
    for relative, content in files.items():
        target = repo / relative
        if content is None:
            target.unlink(missing_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(content, indent=2) if isinstance(content, dict) else content,
            encoding="utf-8",
        )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")
