"""The console entry point: help, version, exit codes and error handling."""

from __future__ import annotations

import sys

import pytest

from ifinjected import __version__, cli
from ifinjected.privacy import RedactionContext, strip_control


def run_main(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["ifinjected", *args])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    code = exit_info.value.code
    return code if isinstance(code, int) else 0


def test_version(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_main(monkeypatch, "--version") == 0
    assert capsys.readouterr().out.strip() == f"ifinjected {__version__}"


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_explains_the_question_and_the_promises(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    assert run_main(monkeypatch, flag) == 0
    # Rich colours the help where it detects CI (GitHub Actions); compare the plain text.
    out = " ".join(strip_control(capsys.readouterr().out).split())
    assert "prompt-injected coding agent" in out
    assert "Read-only and offline" in out
    assert "never read or printed" in out
    assert "--version" in out


def test_no_arguments_shows_usage_with_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch) == 2
    captured = capsys.readouterr()
    assert "Usage" in captured.out + captured.err


def test_unknown_option_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, "--bogus") == 2
    assert "No such option" in strip_control(capsys.readouterr().err)


def test_unexpected_errors_print_one_redacted_line_and_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken() -> None:
        raise RuntimeError(
            "cannot parse /home/alice/.claude/settings.json near ANTHROPIC_API_KEY=sk-ant-x1"
        )

    monkeypatch.setattr(cli, "app", broken)
    monkeypatch.setattr(
        RedactionContext,
        "current",
        classmethod(lambda cls: RedactionContext("/home/alice", "alice", "alice-laptop")),
    )
    monkeypatch.delenv("IFINJECTED_DEBUG", raising=False)
    assert run_main(monkeypatch) == 2
    err = capsys.readouterr().err
    assert (
        "internal error: cannot parse ~/.claude/settings.json near ANTHROPIC_API_KEY=<redacted>"
    ) in err
    assert "sk-ant-x1" not in err
    assert "/home/alice" not in err
    assert "Traceback" not in err


def test_debug_variable_shows_the_real_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "app", broken)
    monkeypatch.setenv("IFINJECTED_DEBUG", "1")
    monkeypatch.setattr(sys, "argv", ["ifinjected"])
    with pytest.raises(RuntimeError, match="boom"):
        cli.main()


def test_rich_tracebacks_with_local_variables_are_disabled() -> None:
    assert cli.app.pretty_exceptions_enable is False
