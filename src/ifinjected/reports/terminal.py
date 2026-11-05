"""Terminal output of already redacted data.

Collected text (paths, setting values, server names) is added as plain ``Text``, never as
Rich markup, so an MCP server called ``[bold]x`` is printed as it is.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ifinjected.models import DEFAULT_LEVELS, Family, Policy, SensitiveItem, Severity, Snapshot

_REDACTION_NAMES = {
    "home_path": ("home path", "home paths"),
    "user_name": ("user name", "user names"),
    "host_name": ("host name", "host names"),
    "secret_value": ("secret value", "secret values"),
    "url_credentials": ("URL credential", "URL credentials"),
    "token": ("token", "tokens"),
    "private_key": ("private key", "private keys"),
}

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def redaction_line(snapshot: Snapshot) -> str | None:
    """'Redacted from this output: 3 home paths, 1 token', or None if nothing was."""
    if not snapshot.redactions:
        return None
    parts = []
    for item in snapshot.redactions:
        singular, plural = _REDACTION_NAMES.get(item.kind, (item.kind, item.kind))
        parts.append(f"{item.count} {singular if item.count == 1 else plural}")
    return "Redacted from this output: " + ", ".join(parts)


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


def _item_detail(item: SensitiveItem) -> str:
    """The facts of an item worth a column: key type and fingerprint, profiles, hosts."""
    parts = []
    for key in ("key_type", "fingerprint"):
        value = item.fact(key)
        if value:
            parts.append(value)
    if item.readable_by_others:
        parts.append("readable by other users")
    return "  ".join(parts)


def render_inventory(snapshot: Snapshot, console: Console) -> None:
    """The sensitive items on this machine, most severe first, grouped by kind."""
    console.print(Text("Sensitive items on this machine", style="bold"))
    console.print(
        Text("Found by name and file header only: no credential value was read.", style="dim")
    )
    console.print()
    if not snapshot.items:
        console.print(Text("None of the known kinds of credentials were found."))
    else:
        order = list(Severity)[::-1]
        items = sorted(snapshot.items, key=lambda i: (order.index(i.severity), i.id, i.path))
        table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold")
        table.add_column("Risk", no_wrap=True)
        table.add_column("What", no_wrap=True)
        table.add_column("Where", overflow="fold")
        table.add_column("Details", overflow="fold", style="dim")
        for item in items:
            table.add_row(
                Text(item.severity.value.upper(), style=_SEVERITY_STYLE[item.severity]),
                Text(item.title),
                Text(display_path(item.path)),
                Text(_item_detail(item)),
            )
        console.print(table)
    for skipped in snapshot.skipped:
        console.print(
            Text(f"Not read: {display_path(skipped.path)} {skipped.reason}", style="yellow")
        )
    line = redaction_line(snapshot)
    if line:
        console.print()
        console.print(Text(line, style="dim"))
