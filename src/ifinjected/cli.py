"""Command-line interface: parses arguments and wires the layers together.

No diagnosis logic lives here; commands call adapters, the inventory, rules and renderers.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ifinjected import __version__
from ifinjected.config import PolicyError, apply_overrides, load_policy
from ifinjected.exit_codes import ExitCode
from ifinjected.homes import Platform
from ifinjected.models import AgentId, Policy
from ifinjected.orchestrator import inspect_agent_policies, inspect_inventory
from ifinjected.privacy import RedactionContext, Redactor, redacted_with_counts
from ifinjected.reports.agents import render_agents
from ifinjected.reports.terminal import render_inventory, render_policy

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


_WORKSPACE_OPTION = typer.Option(
    "--workspace",
    metavar="PATH",
    help="The project the agents work in; its .ifinjected.toml and project settings are read "
    "(default: here).",
)


@app.command()
def policy(workspace: Annotated[Path, _WORKSPACE_OPTION] = Path()) -> None:
    """Show the policy that applies: .ifinjected.toml in the workspace, or the defaults.

    The file is read as data, never run. A file that cannot be used is reported with the
    key at fault and exits with code 2.
    """
    redactor = Redactor(RedactionContext.current())
    effective = _policy_or_exit(workspace.absolute(), redactor)
    render_policy(
        redactor.redact(effective),
        redactor.text(str(workspace.absolute())),
        Console(highlight=False),
    )


_DEEP_OPTION = typer.Option(
    "--deep",
    help="Also parse credential files for their structure (profile and host names); "
    "values are dropped while parsing and never shown.",
)
_ENV_OPTION = typer.Option(
    "--include-env", help="List the variable names in .env files (never their values)."
)


def _policy_or_exit(workspace: Path, redactor: Redactor) -> Policy:
    try:
        return load_policy(workspace)
    except PolicyError as error:
        typer.echo(f"ifinjected: {redactor.text(str(error))}", err=True)
        raise typer.Exit(ExitCode.ERROR) from None


@app.command()
def inventory(
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    deep: Annotated[bool, _DEEP_OPTION] = False,
    include_env: Annotated[bool, _ENV_OPTION] = False,
) -> None:
    """List the credentials and other sensitive items that exist on this machine.

    Found by location, permissions and file header only: a credential's value is never
    read, kept or shown. This is what any agent running as you could start from.
    """
    redactor = Redactor(RedactionContext.current())
    root = workspace.absolute()
    effective = apply_overrides(
        _policy_or_exit(root, redactor),
        deep=True if deep else None,
        include_env=True if include_env else None,
    )
    snapshot = inspect_inventory(Platform.current(), effective, root)
    redacted, counts = redacted_with_counts(snapshot)
    render_inventory(dataclasses.replace(redacted, redactions=counts), Console(highlight=False))


_AGENT_OPTION = typer.Option(
    "--agent", help="Only this agent (repeat for several). Default: every agent found."
)


@app.command()
def agents(
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    agent: Annotated[list[AgentId] | None, _AGENT_OPTION] = None,
) -> None:
    """Show how each coding agent is configured for this workspace, layer by layer.

    Settings files are read as data, never run: the permission mode, how each way of
    reading a file is gated, the read rules with the line they come from, the sandbox,
    and the MCP servers and hooks the agent would start.
    """
    redactor = Redactor(RedactionContext.current())
    root = workspace.absolute()
    effective = apply_overrides(_policy_or_exit(root, redactor), agents=tuple(agent or ()))
    snapshot = inspect_agent_policies(Platform.current(), effective, root)
    redacted, counts = redacted_with_counts(snapshot)
    render_agents(dataclasses.replace(redacted, redactions=counts), Console(highlight=False))


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
