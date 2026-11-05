"""docs/cli.md, generated from the command line itself so the two can never disagree."""

from __future__ import annotations

import enum
import inspect
from pathlib import PurePath
from typing import Any

import typer
from typer.core import TyperArgument, TyperGroup, TyperOption

from ifinjected.cli import app

_INTRO = """\
# Command line

`ifinjected` with no command runs `scan`. Every command is read-only and offline, except
`prove --run` (a fixed probe; one TCP connection with `--network`) and `diff` (read-only
`git`). Nothing is written except a file you name with `--output`.

Exit codes: `0` done, `1` a failing finding under `--strict`, `2` a usage or policy
error, `3` the context could not be read (an unknown git ref, a sandbox that would not
run), `130` interrupted.

This file is generated from the command line
(`uv run python -m ifinjected.clidocs`); a test fails when the two differ.
"""

# The order a reader needs them in; a command missing here is appended, never dropped.
_ORDER = (
    "scan", "inventory", "agents", "plan", "prove", "diff", "report",
    "card", "share", "badge", "explain", "rules", "policy",
)  # fmt: skip


def _default(param: Any) -> str:
    value = param.default
    if isinstance(param, TyperOption) and param.is_flag:
        return ""
    if value is None or value == () or callable(value):
        return ""
    if isinstance(value, enum.Enum):
        value = value.value
    if isinstance(value, PurePath):
        value = value.as_posix()
    return f"`{value}`"


def _flags(param: Any, ctx: typer.Context) -> str:
    if isinstance(param, TyperArgument):
        return f"`{param.human_readable_name}`"
    names = ", ".join(f"`{name}`" for name in [*param.opts, *param.secondary_opts])
    if param.is_flag:
        return names
    choices = getattr(param.type, "choices", None)
    metavar = param.opts[0].lstrip("-").upper() if choices else param.make_metavar(ctx)
    return f"{names} `{metavar}`"


def _help(param: Any) -> str:
    text = getattr(param, "help", None) or ""
    choices = getattr(param.type, "choices", None)
    if choices:
        text = f"{text} One of: {', '.join(f'`{c}`' for c in choices)}.".strip()
    return text.replace("|", "\\|").replace("\n", " ")


def _section(name: str, command: Any, parent: typer.Context) -> list[str]:
    ctx = typer.Context(command, info_name=name, parent=parent)
    params = [p for p in command.params if not getattr(p, "hidden", False)]
    params = [p for p in params if p.name != "help"]
    usage = [f"ifinjected {name}"]
    if any(isinstance(p, TyperOption) for p in params):
        usage.append("[OPTIONS]")
    usage += [p.human_readable_name for p in params if isinstance(p, TyperArgument)]
    out = [f"## `ifinjected {name}`", "", inspect.cleandoc(command.help or ""), ""]
    out += ["```text", " ".join(usage), "```", ""]
    if params:
        out += ["| Option | Default | Meaning |", "|---|---|---|"]
        for param in params:
            out.append(f"| {_flags(param, ctx)} | {_default(param)} | {_help(param)} |")
        out.append("")
    return out


def render_cli_markdown() -> str:
    group = typer.main.get_command(app)
    if not isinstance(group, TyperGroup):
        raise TypeError("the ifinjected app is not a command group")
    root = typer.Context(group, info_name="ifinjected")
    out = [_INTRO]
    names = group.list_commands(root)
    for name in [*(n for n in _ORDER if n in names), *(n for n in names if n not in _ORDER)]:
        command = group.get_command(root, name)
        if command is not None and not command.hidden:
            out += _section(name, command, root)
    return "\n".join(out).rstrip("\n") + "\n"


if __name__ == "__main__":
    from pathlib import Path

    Path("docs/cli.md").write_text(render_cli_markdown(), encoding="utf-8")
