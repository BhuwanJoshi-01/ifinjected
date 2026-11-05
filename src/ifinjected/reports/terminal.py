"""Terminal output of already redacted data.

Collected text (paths, setting values, server names) is added as plain ``Text``, never as
Rich markup, so an MCP server called ``[bold]x`` is printed as it is.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ifinjected.models import DEFAULT_LEVELS, Family, Policy


def display_path(path: str) -> str:
    """A path on one line: newlines, tabs and other control characters shown escaped."""
    out = []
    for char in path:
        if char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 32 or ord(char) == 127:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(char)
    return "".join(out)


def _policy_rows(policy: Policy) -> list[tuple[str, str, str]]:
    """(setting, value, default value) in the order of the policy file."""
    default = Policy()

    def flag(value: bool) -> str:
        return "true" if value else "false"

    def listed(values: tuple[object, ...]) -> str:
        return ", ".join(display_path(str(v)) for v in values) if values else "none"

    every = "every agent found"
    rows = [
        ("scan.agents", listed(policy.agents) if policy.agents else every, every),
        ("scan.deep", flag(policy.deep), flag(default.deep)),
        ("scan.include_env", flag(policy.include_env), flag(default.include_env)),
        ("scan.max_file_bytes", str(policy.max_file_bytes), str(default.max_file_bytes)),
    ]
    for family in Family:
        rows.append((f"policy.{family.policy_key}", policy.level(family), DEFAULT_LEVELS[family]))
    rows += [
        ("accept.items", listed(policy.accept_items), "none"),
        ("accept.mcp_servers", listed(policy.accept_mcp_servers), "none"),
        ("accept.hosts", listed(policy.accept_hosts), "none"),
    ]
    return rows


def render_policy(policy: Policy, workspace: str, console: Console) -> None:
    """The effective policy of a workspace and where each value comes from."""
    if policy.source is not None:
        console.print(Text(f"Policy from {display_path(policy.source)}", style="bold"))
    else:
        console.print(Text("Built-in defaults", style="bold"))
        console.print(Text(f"No .ifinjected.toml in {display_path(workspace)}", style="dim"))
    console.print()
    table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold")
    table.add_column("Setting", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_column("")
    for name, value, default in _policy_rows(policy):
        note = "" if value == default or policy.source is None else f"default: {default}"
        table.add_row(Text(name), Text(str(value)), Text(note, style="dim"))
    console.print(table)
    console.print()
    console.print(
        Text(
            "deny fails --strict, warn is reported, allow is information only. Accepted items, "
            "MCP servers and hosts are still reported, as accepted.",
            style="dim",
        )
    )
