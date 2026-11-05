"""How an agent could reach one path: the worst way in, and what stands in front of it.

For each channel of the agent, in turn:

1. an enabled OS sandbox that applies to the channel and refuses the path closes it;
2. otherwise the agent's rules for that channel decide (by the agent's precedence);
3. otherwise the channel's default gate applies (inside or outside the working dirs).

The reach is then the worst over the channels:

* ``no_approval``: some channel opens without anyone's approval and no rule denies the
  path anywhere;
* ``bypassable_rule``: a rule denies the path on some channel, yet another channel opens
  without a human: the rule gives a false sense of safety, which is worse than none;
* ``after_approval``: every open channel asks a human or a classifier first;
* ``blocked_by_rule`` / ``blocked_by_sandbox``: every channel is closed, by the agent's
  own rules or (only) by the sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass

from ifinjected.models import Reach
from ifinjected.policy.model import (
    Channel,
    ChannelPolicy,
    EffectivePolicy,
    Gate,
    Precedence,
    ReadRule,
)
from ifinjected.policy.patterns import inside, matches

_GATE_ORDER = (Gate.NONE, Gate.AUTOMATED, Gate.HUMAN, Gate.DENIED)
_DENY_FIRST = {Gate.DENIED: 0, Gate.HUMAN: 1, Gate.AUTOMATED: 2, Gate.NONE: 3}


@dataclass(frozen=True, slots=True)
class ChannelReach:
    """What one channel says about one path. ``rule`` is the rule that decided, if any;
    ``by_sandbox`` whether the OS sandbox closed it."""

    channel: ChannelPolicy
    gate: Gate
    rule: ReadRule | None = None
    by_sandbox: bool = False


@dataclass(frozen=True, slots=True)
class ReachResult:
    """The reach of a path for one agent, the channel it comes through, and the rule a
    bypass goes around (for ``bypassable_rule``)."""

    reach: Reach
    via: ChannelReach | None
    bypassed: ReadRule | None = None
    channels: tuple[ChannelReach, ...] = ()
    uncertain: bool = False


def _sandbox_refuses(policy: EffectivePolicy, path: str) -> bool:
    sandbox = policy.sandbox
    if not sandbox.effective:
        return False
    if any(matches(pattern, path) for pattern in sandbox.read_deny):
        return True
    if sandbox.read_only is not None:
        return not any(matches(pattern, path) for pattern in sandbox.read_only)
    return False


def _rule_for(policy: EffectivePolicy, channel: Channel, path: str) -> ReadRule | None:
    applicable = [r for r in policy.rules if channel in r.channels and matches(r.pattern, path)]
    if not applicable:
        return None
    if policy.precedence is Precedence.LAST_MATCH:
        return applicable[-1]
    return min(applicable, key=lambda r: _DENY_FIRST[r.decision])


def channel_reach(policy: EffectivePolicy, channel: ChannelPolicy, path: str) -> ChannelReach:
    if channel.sandboxed and _sandbox_refuses(policy, path):
        return ChannelReach(channel, Gate.DENIED, by_sandbox=True)
    rule = _rule_for(policy, channel.channel, path)
    if rule is not None:
        return ChannelReach(channel, rule.decision, rule=rule)
    in_working_dir = any(inside(d, path) for d in policy.working_dirs)
    return ChannelReach(channel, channel.gate_inside if in_working_dir else channel.gate_outside)


def reach_of(policy: EffectivePolicy, path: str) -> ReachResult:
    """How ``policy``'s agent could read the file at absolute ``path``."""
    results = tuple(channel_reach(policy, channel, path) for channel in policy.channels)
    uncertain = bool(policy.unknowns)
    if not results:
        return ReachResult(Reach.UNKNOWN, None, uncertain=True)
    open_ = sorted((r for r in results if r.gate.opens), key=lambda r: _GATE_ORDER.index(r.gate))
    denied_by_rule = [r for r in results if r.rule is not None and r.rule.decision is Gate.DENIED]
    if open_:
        best = open_[0]
        if denied_by_rule and best.gate in {Gate.NONE, Gate.AUTOMATED}:
            return ReachResult(
                Reach.BYPASSABLE_RULE, best, denied_by_rule[0].rule, results, uncertain
            )
        if best.gate is Gate.NONE:
            return ReachResult(Reach.NO_APPROVAL, best, None, results, uncertain)
        bypassed = denied_by_rule[0].rule if denied_by_rule else None
        return ReachResult(Reach.AFTER_APPROVAL, best, bypassed, results, uncertain)
    if all(r.by_sandbox for r in results):
        return ReachResult(Reach.BLOCKED_BY_SANDBOX, None, None, results, uncertain)
    return ReachResult(Reach.BLOCKED_BY_RULE, None, None, results, uncertain)
