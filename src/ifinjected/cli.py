"""Command-line interface: parses arguments and wires the layers together.

No diagnosis logic lives here; commands call adapters, the inventory, rules and renderers.
"""

from __future__ import annotations

import os
import sys
from typing import Annotated

import typer

from ifinjected import __version__
from ifinjected.exit_codes import ExitCode
from ifinjected.privacy import RedactionContext, Redactor

HELP = (
    "What could a prompt-injected coding agent reach on this machine? For Claude Code, "
    "Codex, Gemini CLI, Cursor, opencode and Copilot CLI: which credentials it could read, "
    "with or without an approval, and where it could send them.\n\n"
    "Read-only and offline: agent configuration is read as data and never run, credential "
    "values are never read or printed, nothing is written and nothing is sent anywhere."
)

app = typer.Typer(
    name="ifinjected",
    help=HELP,
    no_args_is_help=True,
    add_completion=False,
    # Rich tracebacks print local variables, which can hold environment values.
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"ifinjected {__version__}")
        raise typer.Exit()


@app.callback()
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Global options (the help text comes from HELP)."""


def main() -> None:
    """Console entry point.

    Typer reports usage errors itself (exit code 2) and turns Ctrl+C into 130. Anything
    else that escapes is a bug: print one redacted line instead of a traceback, which
    could contain local values, and exit with 2. ``IFINJECTED_DEBUG=1`` shows the
    traceback.
    """
    try:
        app()
    except Exception as exc:  # SystemExit (normal exits) is not an Exception
        if os.environ.get("IFINJECTED_DEBUG"):
            raise
        message = Redactor(RedactionContext.current()).text(str(exc)) or type(exc).__name__
        typer.echo(
            f"ifinjected: internal error: {message}\n"
            "Run it again with IFINJECTED_DEBUG=1 to see the traceback, and please report it.",
            err=True,
        )
        sys.exit(ExitCode.ERROR)
