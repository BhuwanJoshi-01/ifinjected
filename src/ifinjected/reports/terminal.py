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


_FACT_LABELS = {
    "key_type": None,
    "fingerprint": None,
    "profiles": "profiles",
    "static_keys": "static keys",
    "temporary_keys": "temporary keys",
    "sso": "SSO",
    "process": "credential process",
    "type": "type",
    "hosts": "hosts",
    "machines": "machines",
    "registries": "registries",
    "repositories": "repositories",
    "credential_store": "credential store",
    "credential_helpers": "helpers",
    "inline_registries": "inline",
    "credentials": "holds",
    "plugins": "uses",
}


def _item_detail(item: SensitiveItem) -> str:
    """The facts of an item worth showing: key type and fingerprint, profiles, hosts."""
    parts = []
    for fact in item.facts:
        if fact.key not in _FACT_LABELS or not fact.value:
            continue
        label = _FACT_LABELS[fact.key]
        parts.append(fact.value if label is None else f"{label}: {fact.value}")
    if item.readable_by_others:
        parts.append("readable by other users")
    return " · ".join(parts)


def render_inventory(snapshot: Snapshot, console: Console) -> None:
    """The sensitive items on this machine, most severe first: what, then where."""
    console.print(Text("Sensitive items on this machine", style="bold"))
    console.print(
        Text("Found by name and file header only: no credential value was read.", style="dim")
    )
    console.print()
    if not snapshot.items:
        console.print(Text("None of the known kinds of credentials were found."))
    order = list(Severity)[::-1]
    items = sorted(snapshot.items, key=lambda i: (order.index(i.severity), i.id, i.path))
    for item in items:
        heading = Text()
        heading.append(f"{item.severity.value.upper():<7}", style=_SEVERITY_STYLE[item.severity])
        heading.append(item.title)
        console.print(heading)
        where = Text("       ")
        where.append(display_path(item.path))
        detail = _item_detail(item)
        if detail:
            where.append(f"  {detail}", style="dim")
        console.print(where)
    for skipped in snapshot.skipped:
        console.print(
            Text(f"Not read: {display_path(skipped.path)} {skipped.reason}", style="yellow")
        )
    counts = Text()
    by_severity = [sum(1 for i in snapshot.items if i.severity is s) for s in order]
    if snapshot.items:
        console.print()
        summary = ", ".join(f"{n} {s.value}" for n, s in zip(by_severity, order, strict=True) if n)
        counts.append(f"{len(snapshot.items)} items: {summary}")
        console.print(counts)
    redacted = redaction_line(snapshot)
    if redacted:
        console.print(Text(redacted, style="dim"))
