"""Exit codes are a contract: scripts and CI jobs depend on them."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    """The scan ran. Findings, even failing ones, do not change this."""

    STRICT_FAILURE = 1
    """``--strict`` was given and a finding reached the policy's fail level (``deny``)."""

    ERROR = 2
    """Wrong usage, or the tool itself failed."""

    CONTEXT_UNAVAILABLE = 3
    """Something the command needs is missing, e.g. the Git base ref of ``diff --base``."""

    INTERRUPTED = 130
    """Stopped with Ctrl+C (128 + SIGINT, as shells report it)."""
