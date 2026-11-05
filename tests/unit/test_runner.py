import pytest

from ifinjected.models import FailureKind, ProbeFailure
from ifinjected.runner import CommandResult, Outcome, probe_failure


def test_only_ok_outcome_counts_as_ok() -> None:
    assert CommandResult(("true",), Outcome.OK, returncode=0).ok
    for outcome in Outcome:
        if outcome is not Outcome.OK:
            assert not CommandResult(("x",), outcome).ok


def test_successful_result_is_not_a_failure() -> None:
    assert probe_failure("git", CommandResult(("git",), Outcome.OK, 0)) is None


@pytest.mark.parametrize(
    ("result", "kind", "detail"),
    [
        (
            CommandResult(("git",), Outcome.NOT_FOUND, error="No such file"),
            FailureKind.NOT_FOUND,
            "git was not found",
        ),
        (
            CommandResult(("git",), Outcome.PERMISSION),
            FailureKind.PERMISSION_DENIED,
            "permission denied when starting git",
        ),
        (
            CommandResult(("git",), Outcome.TIMEOUT, duration=5.04),
            FailureKind.TIMEOUT,
            "git did not finish within 5.0 s and was stopped",
        ),
        (
            CommandResult(
                ("git",),
                Outcome.NONZERO,
                returncode=128,
                stderr="\nfatal: not a git repository: /srv\nsecond line\n",
            ),
            FailureKind.NONZERO_EXIT,
            "git exited with code 128: fatal: not a git repository: /srv",
        ),
        (
            CommandResult(("python",), Outcome.OS_ERROR, error="Exec format error"),
            FailureKind.OS_ERROR,
            "python could not be started: Exec format error",
        ),
    ],
)
def test_failed_results_become_probe_failures(
    result: CommandResult, kind: FailureKind, detail: str
) -> None:
    failure = probe_failure("git worktree list", result)
    assert failure == ProbeFailure("git worktree list", kind, detail)


def test_failure_detail_is_kept_short() -> None:
    result = CommandResult(("x",), Outcome.NONZERO, returncode=1, stderr="e" * 5000)
    failure = probe_failure("x", result)
    assert failure is not None
    assert len(failure.detail) == 200
    assert failure.detail.endswith("…")


def test_failure_detail_uses_stdout_when_stderr_is_empty() -> None:
    result = CommandResult(
        ("docker", "compose", "ls"),
        Outcome.NONZERO,
        returncode=1,
        stdout="Cannot connect to the Docker daemon\n",
    )
    failure = probe_failure("docker", result)
    assert failure is not None
    assert failure.detail == "docker exited with code 1: Cannot connect to the Docker daemon"


def test_failure_detail_prefers_stderr() -> None:
    result = CommandResult(("x",), Outcome.NONZERO, returncode=1, stdout="out", stderr="err")
    failure = probe_failure("x", result)
    assert failure is not None
    assert failure.detail == "x exited with code 1: err"
