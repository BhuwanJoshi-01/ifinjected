"""The installed command and ``python -m`` start the same CLI."""

from __future__ import annotations

import sys
import sysconfig
from pathlib import Path

import pytest

from ifinjected import __version__
from ifinjected.runner import Outcome, SubprocessRunner


def _console_script(name: str = "ifinjected") -> Path:
    if sys.platform == "win32":
        name += ".exe"
    return Path(sysconfig.get_path("scripts")) / name


@pytest.mark.parametrize(
    "argv",
    [
        [sys.executable, "-m", "ifinjected", "--version"],
        [str(_console_script()), "--version"],
    ],
    ids=["python -m", "console script"],
)
def test_entry_point_prints_the_version(argv: list[str]) -> None:
    result = SubprocessRunner().run(argv, timeout=30)
    assert result.outcome is Outcome.OK, result.stderr
    assert result.stdout.strip() == f"ifinjected {__version__}"
