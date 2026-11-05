"""Every sensitive item, for every agent: how the agent could get at it.

Files go through the reach engine path by path. Two kinds of items have no path a rule
could name:

* **environment variables** are inherited by every command the agent runs, so one
  ``echo $OPENAI_API_KEY`` or ``env`` prints them. Their reach is the best gate among the
  agent's shell channels; no file rule applies, and a sandbox does not strip the
  environment unless told to;
* **credential sockets** (ssh-agent, Docker, gpg-agent) are used by running a program
  (``ssh``, ``docker``), so their reach is that of arbitrary shell commands. A sandbox
  may refuse sockets; when one applies, the result is marked uncertain.
"""

from __future__ import annotations

from dataclasses import dataclass

from ifinjected.agents.base import AgentReport
from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import AgentId, Proof, Reach, SensitiveItem, SourceRef
from ifinjected.policy.model import Channel, ChannelPolicy, EffectivePolicy, Gate
from ifinjected.policy.reach import reach_of

_SOCKETS = {"socket.ssh_agent", "socket.docker", "socket.gpg_agent"}
_GATE_ORDER = (Gate.NONE, Gate.AUTOMATED, Gate.HUMAN, Gate.DENIED)
_SHELLS = (Channel.SHELL_RECOGNIZED, Channel.SHELL_ARBITRARY)


@dataclass(frozen=True, slots=True)
class Exposure:
    """How one agent could get at one item.

    ``channel`` and ``gate`` describe the way in (``None`` when blocked); ``bypassed``
    is the rule a way in goes around, with the line it was written on.
    """

    agent: AgentId
    item: str
    path: str
    reach: Reach
    channel: Channel | None = None
    gate: Gate | None = None
    sandboxed: bool = False
    bypassed: SourceRef | None = None
    bypassed_pattern: str | None = None
    uncertain: bool = False
    proof: Proof = Proof.CLAIMED


def _gate_reach(gate: Gate) -> Reach:
    if gate is Gate.NONE:
        return Reach.NO_APPROVAL
    if gate is Gate.DENIED:
        return Reach.BLOCKED_BY_RULE
    return Reach.AFTER_APPROVAL


def _best(channels: list[ChannelPolicy]) -> ChannelPolicy | None:
    open_ = [c for c in channels if c.gate_inside.opens or c.gate_outside.opens]
    if not open_:
        return None
    return min(open_, key=lambda c: _GATE_ORDER.index(_easiest(c)))


def _easiest(channel: ChannelPolicy) -> Gate:
    return min(channel.gate_inside, channel.gate_outside, key=_GATE_ORDER.index)


def _through_shell(
    policy: EffectivePolicy, agent: AgentId, item: SensitiveItem, kinds: tuple[Channel, ...]
) -> Exposure:
    channels = [c for c in policy.channels if c.channel in kinds]
    best = _best(channels)
    if best is None:
        reach = Reach.BLOCKED_BY_RULE if channels else Reach.UNKNOWN
        return Exposure(
            agent, item.id, item.path, reach, uncertain=not channels or bool(policy.unknowns)
        )
    gate = _easiest(best)
    socket_in_sandbox = item.id in _SOCKETS and best.sandboxed
    return Exposure(
        agent,
        item.id,
        item.path,
        _gate_reach(gate),
        channel=best.channel,
        gate=gate,
        sandboxed=best.sandboxed,
        uncertain=bool(policy.unknowns) or socket_in_sandbox,
    )


def exposure_of(policy: EffectivePolicy, item: SensitiveItem) -> Exposure:
    agent = policy.agent
    if item.path == ENVIRONMENT:
        if policy.inherits_secret_env is False:
            return Exposure(agent, item.id, item.path, Reach.BLOCKED_BY_RULE)
        return _through_shell(policy, agent, item, _SHELLS)
    if item.id in _SOCKETS:
        return _through_shell(policy, agent, item, (Channel.SHELL_ARBITRARY,))
    result = reach_of(policy, item.path)
    via = result.via
    return Exposure(
        agent,
        item.id,
        item.path,
        result.reach,
        channel=via.channel.channel if via else None,
        gate=via.gate if via else None,
        sandboxed=via.channel.sandboxed if via else False,
        bypassed=result.bypassed.source if result.bypassed else None,
        bypassed_pattern=result.bypassed.pattern if result.bypassed else None,
        uncertain=result.uncertain,
    )


def exposures(
    agents: tuple[AgentReport, ...], items: tuple[SensitiveItem, ...]
) -> tuple[Exposure, ...]:
    """Every (agent, item) pair, worst first within each agent."""
    found: list[Exposure] = []
    for report in agents:
        if not report.found or report.policy is None:
            continue
        per_agent = [exposure_of(report.policy, item) for item in items]
        per_agent.sort(key=lambda e: (e.reach.rank, e.item, e.path))
        found.extend(per_agent)
    return tuple(found)
