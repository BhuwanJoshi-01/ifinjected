"""Terminal view of each agent's configuration layers and effective policy."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from ifinjected.agents.base import AgentReport
from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import Reach, SensitiveItem, Snapshot, SourceRef
from ifinjected.policy.exposure import Exposure
from ifinjected.policy.model import Channel, ChannelPolicy, Gate
from ifinjected.reports.terminal import display_path, redaction_line

_GATE_TEXT = {
    Gate.NONE: "no approval",
    Gate.AUTOMATED: "a classifier decides",
    Gate.HUMAN: "asks you",
    Gate.DENIED: "refused",
}
_GATE_STYLE = {
    Gate.NONE: "bold red",
    Gate.AUTOMATED: "yellow",
    Gate.HUMAN: "green",
    Gate.DENIED: "green",
}
_CHANNEL_TEXT = {
    Channel.FILE_TOOL: "file tools",
    Channel.SHELL_RECOGNIZED: "read-only commands",
    Channel.SHELL_ARBITRARY: "other commands",
    Channel.MCP: "MCP server",
    Channel.HOOK: "hook",
}


def where(source: SourceRef | None) -> str:
    if source is None:
        return ""
    line = f":{source.line}" if source.line is not None else ""
    return display_path(source.path) + line


def _channel(console: Console, channel: ChannelPolicy) -> None:
    line = Text(f"    {_CHANNEL_TEXT[channel.channel]:<20}")
    if channel.gate_inside is channel.gate_outside:
        line.append(
            _GATE_TEXT[channel.gate_inside] + " anywhere", style=_GATE_STYLE[channel.gate_inside]
        )
    else:
        line.append("in the workspace: ")
        line.append(_GATE_TEXT[channel.gate_inside], style=_GATE_STYLE[channel.gate_inside])
        line.append(" · elsewhere: ")
        line.append(_GATE_TEXT[channel.gate_outside], style=_GATE_STYLE[channel.gate_outside])
    if channel.sandboxed:
        line.append(" (in the sandbox)", style="dim")
    console.print(line)
    if channel.note:
        console.print(Text(f"    {'':<20}{channel.note}", style="dim"))


def render_agent(report: AgentReport, console: Console) -> None:
    console.print(Text(report.agent.display_name, style="bold underline"))
    if not report.found:
        console.print(Text("  Not found on this machine.", style="dim"))
        return
    console.print(Text("  Configuration", style="bold"))
    if not report.layers:
        console.print(Text("    no settings files: the defaults apply", style="dim"))
    for layer in report.layers:
        line = Text(f"    {layer.scope.value:<8} {display_path(layer.path)}")
        if layer.trusted is False:
            line.append("  (workspace not trusted: its allow rules wait)", style="yellow")
        if layer.skipped:
            line.append(f"  not read: {layer.skipped}", style="yellow")
        console.print(line)
    console.print(Text("  Settings", style="bold"))
    for name, value, source in report.settings:
        line = Text(f"    {name:<36} {value}")
        if source is not None:
            line.append(f"  {where(source)}", style="dim")
        console.print(line)
    policy = report.policy
    if policy is not None:
        console.print(Text("  How it can read a file", style="bold"))
        for channel in policy.channels:
            _channel(console, channel)
        sandbox = policy.sandbox
        state = "off"
        if sandbox.enabled:
            state = "on" if sandbox.available is not False else "on, but it cannot run here"
        line = Text(f"    {'sandbox':<20}{state}")
        if sandbox.enabled and sandbox.available is not False:
            line.append(f" · network: {sandbox.network.value}", style="dim")
        console.print(line)
        if policy.rules:
            console.print(Text("  Read rules", style="bold"))
            for rule in policy.rules:
                line = Text(f"    {_GATE_TEXT[rule.decision]:<12} {display_path(rule.pattern)}")
                line.append(f"  {where(rule.source)}", style="dim")
                console.print(line)
    if report.mcp_servers:
        console.print(Text("  MCP servers", style="bold"))
        for server in report.mcp_servers:
            what = server.package or server.program or server.host or server.transport
            line = Text(
                f"    {server.name:<20} {server.scope.value:<8} {server.transport:<6} {what}"
            )
            if server.env_names:
                line.append(f"  env: {', '.join(server.env_names)}", style="dim")
            if server.approved is None:
                line.append("  (asks before first use)", style="dim")
            elif server.approved is False:
                line.append("  (disabled)", style="dim")
            console.print(line)
    if report.hooks:
        console.print(Text("  Hooks (run with your full access)", style="bold"))
        for hook in report.hooks:
            line = Text(f"    {hook.event:<20} {hook.program}")
            line.append(f"  {where(hook.source)}", style="dim")
            console.print(line)
    for note in (*report.notes, *(policy.unknowns if policy else ())):
        console.print(Text(f"  Note: {note}", style="yellow"))


_REACH_TEXT = {
    Reach.NO_APPROVAL: ("without approval", "bold red"),
    Reach.BYPASSABLE_RULE: ("around a deny rule", "bold red"),
    Reach.AFTER_APPROVAL: ("after an approval", "yellow"),
    Reach.BLOCKED_BY_RULE: ("blocked by a rule", "green"),
    Reach.BLOCKED_BY_SANDBOX: ("blocked by the sandbox", "green"),
    Reach.UNKNOWN: ("undecided", "dim"),
}
_CHANNEL_VIA = {
    Channel.FILE_TOOL: "its file tools",
    Channel.SHELL_RECOGNIZED: "a read-only command such as cat",
    Channel.SHELL_ARBITRARY: "a command that opens the file itself",
    Channel.MCP: "an MCP server",
    Channel.HOOK: "a hook",
}


def render_exposures(
    exposures: list[Exposure], items: dict[tuple[str, str], SensitiveItem], console: Console
) -> None:
    shown = [e for e in exposures if e.reach is not Reach.NOT_PRESENT]
    if not shown:
        return
    console.print(Text("  What an injected agent could reach", style="bold"))
    for exposure in shown:
        text, style = _REACH_TEXT[exposure.reach]
        if exposure.reach is Reach.AFTER_APPROVAL and exposure.gate is Gate.AUTOMATED:
            text, style = "after the classifier", "bold yellow"
        item = items.get((exposure.item, exposure.path))
        title = item.title if item else exposure.item
        line = Text("    ")
        line.append(f"{text:<24}", style=style)
        line.append(title)
        console.print(line)
        detail = Text(f"    {'':<24}{display_path(exposure.path)}", style="dim")
        if exposure.channel is not None and exposure.reach.reachable:
            via = _CHANNEL_VIA[exposure.channel]
            if exposure.path == ENVIRONMENT:
                via = "a shell command such as env"
            detail.append(f" · via {via}")
            if exposure.sandboxed:
                detail.append(" in the sandbox")
        if exposure.bypassed is not None:
            detail.append(f" · goes around {where(exposure.bypassed)}")
        if exposure.uncertain:
            detail.append(" · uncertain")
        console.print(detail)


def render_agents(snapshot: Snapshot, console: Console) -> None:
    if not snapshot.agents:
        console.print(Text("No supported coding agent was found on this machine."))
    items = {(i.id, i.path): i for i in snapshot.items}
    for index, report in enumerate(snapshot.agents):
        if index:
            console.print()
        render_agent(report, console)
        render_exposures([e for e in snapshot.exposures if e.agent is report.agent], items, console)
    line = redaction_line(snapshot)
    if line:
        console.print()
        console.print(Text(line, style="dim"))
