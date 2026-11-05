import pytest

from ifinjected.runner import CommandResult, CommandRunner, Outcome
from tests.fakes import FakeRunner, UnexpectedCommandError


def test_fake_runner_answers_scripted_commands_and_records_calls() -> None:
    fake = FakeRunner()
    fake.script("codex", "--version", stdout="codex-cli 0.130.0\n")
    runner: CommandRunner = fake
    result = runner.run(["codex", "--version"], timeout=8, env_overrides={"LC_ALL": "C"})
    assert result.ok
    assert result.stdout == "codex-cli 0.130.0\n"
    assert fake.calls[0].argv == ("codex", "--version")
    assert fake.calls[0].env_overrides == {"LC_ALL": "C"}


def test_fake_runner_fails_the_test_on_unscripted_commands() -> None:
    with pytest.raises(UnexpectedCommandError, match="rm"):
        FakeRunner().run(["rm", "-rf", "~/.ssh"], timeout=1)


def test_fake_runner_can_return_any_outcome() -> None:
    fake = FakeRunner()
    fake.script_result(CommandResult(("git",), Outcome.TIMEOUT, duration=5))
    assert fake.run(["git"], timeout=5).outcome is Outcome.TIMEOUT
