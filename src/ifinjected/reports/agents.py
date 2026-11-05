"""Terminal view of each agent's configuration layers and effective policy."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from ifinjected.agents.base import AgentReport
from ifinjected.models import Snapshot, SourceRef
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


def render_agents(snapshot: Snapshot, console: Console) -> None:
    if not snapshot.agents:
        console.print(Text("No supported coding agent was found on this machine."))
    for index, report in enumerate(snapshot.agents):
        if index:
            console.print()
        render_agent(report, console)
    line = redaction_line(snapshot)
    if line:
        console.print()
        console.print(Text(line, style="dim"))
