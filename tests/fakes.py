"""Test doubles for the command runner."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ifinjected.runner import CommandResult, Outcome


class UnexpectedCommandError(AssertionError):
    """Code under test ran a command the test did not script."""


@dataclass(frozen=True)
class Call:
    argv: tuple[str, ...]
    timeout: float
    env_overrides: Mapping[str, str] | None
    cwd: Path | None


@dataclass
class FakeRunner:
    """Answers scripted commands and fails the test on anything else.

    Being strict is the point: code that starts running a new command (or anything that
    could change the system) breaks the tests until someone scripts and reviews it.
    """

    responses: dict[tuple[str, ...], CommandResult] = field(default_factory=dict)
    calls: list[Call] = field(default_factory=list)

    def script(self, *argv: str, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        outcome = Outcome.OK if returncode == 0 else Outcome.NONZERO
        self.responses[argv] = CommandResult(argv, outcome, returncode, stdout, stderr)

    def script_result(self, result: CommandResult) -> None:
        self.responses[result.argv] = result

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        env_overrides: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        key = tuple(argv)
        self.calls.append(Call(key, timeout, env_overrides, cwd))
        if key not in self.responses:
            raise UnexpectedCommandError(f"unscripted command: {list(key)}")
        return self.responses[key]


FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(*parts: str) -> str:
    """Text of a file under tests/fixtures/ (see the README next to each set)."""
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")
