"""Command-line interface: parses arguments and wires the layers together.

No diagnosis logic lives here; commands call adapters, the inventory, rules and renderers.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ifinjected import __version__
from ifinjected.config import PolicyError, apply_overrides, load_policy
from ifinjected.exit_codes import ExitCode
from ifinjected.homes import Platform
from ifinjected.models import AgentId, Policy, Snapshot
from ifinjected.orchestrator import inspect_all, inspect_inventory
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
    invoke_without_command=True,
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
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Global options (the help text comes from HELP). Without a command: scan."""
    if ctx.invoked_subcommand is None:
        _scan(Path(), strict=False, show_all=False, deep=False, include_env=False, agent=None)


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
    snapshot = inspect_all(Platform.current(), effective, root)
    redacted, counts = redacted_with_counts(snapshot)
    render_agents(dataclasses.replace(redacted, redactions=counts), Console(highlight=False))


class Format(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class ReportFormat(StrEnum):
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"


_FORMAT_OPTION = typer.Option("--format", "-f", help="terminal, json, markdown or sarif.")
_STRICT_OPTION = typer.Option("--strict", help="Exit with 1 when a finding fails under the policy.")
_ALL_OPTION = typer.Option("--all", help="List every warning instead of folding them per rule.")


def _rendered(snapshot: Snapshot, output_format: str) -> str:
    from ifinjected.reports.formats import render_json, render_markdown, render_sarif

    if output_format == Format.JSON:
        return render_json(snapshot)
    if output_format == Format.SARIF:
        return render_sarif(snapshot)
    return render_markdown(snapshot)


def _diagnosed(
    workspace: Path, *, deep: bool, include_env: bool, agent: list[AgentId] | None
) -> tuple[Snapshot, Snapshot]:
    """(the diagnosed snapshot, its redacted copy with the redaction counts)."""
    from ifinjected.orchestrator import diagnose

    redactor = Redactor(RedactionContext.current())
    root = workspace.absolute()
    effective = apply_overrides(
        _policy_or_exit(root, redactor),
        agents=tuple(agent or ()),
        deep=True if deep else None,
        include_env=True if include_env else None,
    )
    snapshot = diagnose(inspect_all(Platform.current(), effective, root))
    redacted, counts = redacted_with_counts(snapshot)
    return snapshot, dataclasses.replace(redacted, redactions=counts)


def _scan(
    workspace: Path,
    *,
    strict: bool,
    show_all: bool,
    deep: bool,
    include_env: bool,
    agent: list[AgentId] | None,
    output_format: Format = Format.TERMINAL,
) -> None:
    from ifinjected.models import Status
    from ifinjected.reports.scan import render_scan

    snapshot, redacted = _diagnosed(workspace, deep=deep, include_env=include_env, agent=agent)
    if output_format is Format.TERMINAL:
        render_scan(redacted, Console(highlight=False), show_all=show_all)
    else:
        typer.echo(_rendered(redacted, output_format), nl=False)
    if strict and any(f.status is Status.FAIL for f in snapshot.findings):
        raise typer.Exit(ExitCode.STRICT_FAILURE)


@app.command()
def scan(
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    strict: Annotated[bool, _STRICT_OPTION] = False,
    show_all: Annotated[bool, _ALL_OPTION] = False,
    deep: Annotated[bool, _DEEP_OPTION] = False,
    include_env: Annotated[bool, _ENV_OPTION] = False,
    agent: Annotated[list[AgentId] | None, _AGENT_OPTION] = None,
    output_format: Annotated[Format, _FORMAT_OPTION] = Format.TERMINAL,
) -> None:
    """What could a prompt-injected agent reach here? A grade per agent, then the fixes.

    Read-only and offline: configuration is read as data, credentials are found by
    location and header only, nothing is run, written or sent. Exits with 1 under
    --strict when a finding fails the policy in .ifinjected.toml.
    """
    _scan(
        workspace,
        strict=strict,
        show_all=show_all,
        deep=deep,
        include_env=include_env,
        agent=agent,
        output_format=output_format,
    )


@app.command()
def report(
    output: Annotated[
        Path, typer.Option("--output", "-o", metavar="FILE", help="Where to write; - for stdout.")
    ],
    output_format: Annotated[ReportFormat, _FORMAT_OPTION] = ReportFormat.MARKDOWN,
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    deep: Annotated[bool, _DEEP_OPTION] = False,
    include_env: Annotated[bool, _ENV_OPTION] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a redacted report (Markdown, JSON or SARIF) to a file you name.

    The only command that writes anything, and only the file given with --output; an
    existing file is kept unless --force is given.
    """
    _, redacted = _diagnosed(workspace, deep=deep, include_env=include_env, agent=None)
    text = _rendered(redacted, Format(output_format.value))
    if str(output) == "-":
        typer.echo(text, nl=False)
        return
    if output.exists() and not force:
        typer.echo(f"ifinjected: {output} exists; use --force to overwrite it", err=True)
        raise typer.Exit(ExitCode.ERROR)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"Wrote {output}")


@app.command()
def diff(
    base: Annotated[
        str,
        typer.Option("--base", metavar="REF", help="The ref to compare with (e.g. origin/main)."),
    ],
    head: Annotated[
        str, typer.Option("--head", metavar="REF", help="The ref with the change.")
    ] = "HEAD",
    repo: Annotated[
        Path, typer.Option("--repo", metavar="PATH", help="The repository (default: here).")
    ] = Path(),
    output_format: Annotated[Format, _FORMAT_OPTION] = Format.TERMINAL,
    strict: Annotated[bool, _STRICT_OPTION] = False,
) -> None:
    """Does a change widen what coding agents may do? For pull requests.

    Compares the agent configuration the repository commits (.claude/settings.json,
    .mcp.json, .codex/config.toml, .gemini/settings.json, .cursor/, opencode.json,
    .github/copilot/) between two refs, with read-only git. Exits with 3 when a ref
    cannot be read, and with 1 under --strict when a change fails the policy.
    """
    from ifinjected import __version__
    from ifinjected.diffing import DiffError, diff_findings
    from ifinjected.models import Family, Status, utc_timestamp
    from ifinjected.rules.engine import problem_status
    from ifinjected.runner import SubprocessRunner

    redactor = Redactor(RedactionContext.current())
    root = repo.absolute()
    effective = _policy_or_exit(root, redactor)
    try:
        found = diff_findings(SubprocessRunner(), root, base, head)
    except DiffError as error:
        typer.echo(f"ifinjected: {redactor.text(str(error))}", err=True)
        raise typer.Exit(ExitCode.CONTEXT_UNAVAILABLE) from None
    status = problem_status(effective, Family.DIFF)
    findings = tuple(dataclasses.replace(f, status=status) for f in found)
    snapshot = Snapshot(
        __version__,
        utc_timestamp(),
        Platform.current().system.value,
        workspace=str(root),
        policy=effective,
        findings=findings,
    )
    redacted, counts = redacted_with_counts(snapshot)
    redacted = dataclasses.replace(redacted, redactions=counts)
    if output_format is Format.TERMINAL:
        if not findings:
            typer.echo(f"No change between {base} and {head} widens what coding agents may do.")
        for finding in redacted.findings:
            line = (
                f":{finding.sources[0].line}" if finding.sources and finding.sources[0].line else ""
            )
            typer.echo(f"{finding.status.value.upper():<5} {finding.id}  {finding.summary}{line}")
    else:
        typer.echo(_rendered(redacted, output_format), nl=False)
    if strict and any(f.status is Status.FAIL for f in findings):
        raise typer.Exit(ExitCode.STRICT_FAILURE)


@app.command()
def prove(
    run: Annotated[
        bool, typer.Option("--run", help="Run the probe (without it, only explain).")
    ] = False,
    network: Annotated[
        bool, typer.Option("--network", help="Also try one TCP connection from inside the sandbox.")
    ] = False,
    target: Annotated[
        str, typer.Option("--target", metavar="HOST:PORT", help="Where --network connects.")
    ] = "example.com:443",
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
) -> None:
    """Check the claims against this machine: open credential files under Codex's sandbox.

    A fixed probe calls open() and close() on each credential's path, never read(),
    once directly and once inside the sandbox (codex sandbox --). With --network it
    makes one TCP connection to --target and sends nothing. Other agents' sandboxes
    cannot be run from outside yet; their results stay claimed.
    """
    from ifinjected.models import AgentId as Agent
    from ifinjected.prove.runners import codex_available, run_codex, run_direct
    from ifinjected.prove.verdicts import judge, probe_paths
    from ifinjected.runner import SubprocessRunner

    if not run:
        typer.echo(
            "prove --run opens (never reads) each credential's path directly and inside Codex's\n"
            "sandbox, and reports where the configuration's claims hold. --network also tries one\n"
            "connection to --target from inside the sandbox. Nothing runs without --run."
        )
        return
    snapshot, _ = _diagnosed(workspace, deep=False, include_env=False, agent=None)
    redactor = Redactor(RedactionContext.current())
    codex = next((a for a in snapshot.agents if a.agent is Agent.CODEX and a.found), None)
    if codex is None or not codex_available():
        typer.echo(
            "Codex is not installed here; nothing can be proven yet (other sandboxes are claimed)."
        )
        return
    paths = [path for path, *_ in probe_paths(snapshot, Agent.CODEX)]
    runner = SubprocessRunner()
    connect = target if network else None
    root = workspace.absolute()
    direct = run_direct(runner, paths, None, root)
    sandboxed = run_codex(runner, paths, connect, root)
    if sandboxed.problem:
        typer.echo(f"ifinjected: {redactor.text(sandboxed.problem)}", err=True)
        raise typer.Exit(ExitCode.CONTEXT_UNAVAILABLE)
    rows, findings = judge(snapshot, Agent.CODEX, direct, sandboxed, connect)
    typer.echo("Codex: opened directly / inside codex sandbox")
    for row in rows:
        line = f"  {_opened(row.direct):<8} {_opened(row.sandboxed):<8} {row.title}  {row.path}"
        typer.echo(redactor.text(line))
    if connect is not None:
        state = "connected" if sandboxed.connect == 0 else "refused"
        typer.echo(f"  network: {state} to {target} from inside the sandbox")
    typer.echo("")
    proven = sum(1 for f in findings if f.id == "IFJ-PROVE-002")
    if proven:
        typer.echo(
            f"WARN  IFJ-PROVE-002  Proven: Codex's sandbox opens {proven} credential file(s) above"
        )
    for finding in findings:
        if finding.id != "IFJ-PROVE-002":
            text = f"{finding.status.value.upper():<5} {finding.id}  {finding.summary}"
            typer.echo(redactor.text(text))
    if not findings:
        typer.echo("No claim was contradicted, and nothing reachable was opened.")


def _opened(code: int | None) -> str:
    return "-" if code is None else "opened" if code == 0 else "refused"


class PlanFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


@app.command()
def plan(
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    output_format: Annotated[PlanFormat, _FORMAT_OPTION] = PlanFormat.TEXT,
) -> None:
    """Show the configuration changes that close each agent's exposures. Applies nothing."""
    from ifinjected.plan import make_plan, render_plan_json, render_plan_text

    snapshot, _ = _diagnosed(workspace, deep=False, include_env=False, agent=None)
    steps = make_plan(snapshot, str(Platform.current().home))
    text = render_plan_json(steps) if output_format is PlanFormat.JSON else render_plan_text(steps)
    typer.echo(Redactor(RedactionContext.current()).text(text), nl=False)


def _write_or_print(text: str, output: Path | None, force: bool) -> None:
    if output is None or str(output) == "-":
        typer.echo(text, nl=False)
        return
    if output.exists() and not force:
        typer.echo(f"ifinjected: {output} exists; use --force to overwrite it", err=True)
        raise typer.Exit(ExitCode.ERROR)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"Wrote {output}")


_OUTPUT_OPTION = typer.Option(
    "--output", "-o", metavar="FILE", help="Write here instead of printing."
)
_FORCE_OPTION = typer.Option("--force", help="Overwrite an existing file.")


@app.command()
def card(
    output: Annotated[Path | None, _OUTPUT_OPTION] = None,
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    share_detail: Annotated[
        bool,
        typer.Option("--share-detail", help="Also name the kinds of exposed items (no paths)."),
    ] = False,
    force: Annotated[bool, _FORCE_OPTION] = False,
) -> None:
    """A share card (SVG, 1200x630): your grade per agent and counts, nothing else.

    No path, user name, host name, secret name or server name is on it.
    """
    from ifinjected.reports.card import render_card

    _, redacted = _diagnosed(workspace, deep=False, include_env=False, agent=None)
    _write_or_print(render_card(redacted, detail=share_detail), output, force)


@app.command()
def share(workspace: Annotated[Path, _WORKSPACE_OPTION] = Path()) -> None:
    """One line to post with your card: the grades, and how to check yours."""
    from ifinjected.reports.card import render_share_text

    _, redacted = _diagnosed(workspace, deep=False, include_env=False, agent=None)
    typer.echo(render_share_text(redacted), nl=False)


@app.command()
def badge(
    output: Annotated[Path | None, _OUTPUT_OPTION] = None,
    workspace: Annotated[Path, _WORKSPACE_OPTION] = Path(),
    force: Annotated[bool, _FORCE_OPTION] = False,
) -> None:
    """A small README badge (SVG) with the grade."""
    from ifinjected.reports.card import render_badge

    _, redacted = _diagnosed(workspace, deep=False, include_env=False, agent=None)
    _write_or_print(render_badge(redacted), output, force)


@app.command()
def explain(
    code: Annotated[str, typer.Argument(metavar="CODE", help="A finding code, e.g. IFJ-READ-003.")],
) -> None:
    """Explain a finding: what it means, why it matters, and its sources."""
    from ifinjected.rules.catalog import rule_by_id
    from ifinjected.rules.docs import explain as explanation

    rule = rule_by_id(code)
    if rule is None:
        typer.echo(f"ifinjected: unknown finding code {code}; see ifinjected rules", err=True)
        raise typer.Exit(ExitCode.ERROR)
    typer.echo(explanation(rule), nl=False)


@app.command()
def rules() -> None:
    """List every rule with its code and title."""
    from ifinjected.rules.catalog import builtin_rules

    for rule in builtin_rules():
        typer.echo(f"{rule.id:<18} {rule.title}")


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
