"""The reach engine: the worst way into a path, and what is in front of it (IFJ-020, IFJ-021)."""

from __future__ import annotations

from dataclasses import replace

from ifinjected.models import AgentId, Reach, SourceRef
from ifinjected.policy.model import (
    Channel,
    ChannelPolicy,
    EffectivePolicy,
    Gate,
    Precedence,
    ReadRule,
    SandboxPolicy,
)
from ifinjected.policy.reach import reach_of

KEY = "/home/a/.ssh/id_ed25519"
WORKSPACE = "/home/a/src/app"
ENV = "/home/a/src/app/.env"
FILE_RULES = frozenset({Channel.FILE_TOOL, Channel.SHELL_RECOGNIZED})


def _claude_like(**changes: object) -> EffectivePolicy:
    """Roughly Claude Code in its default mode: the file tool reads anywhere without a
    prompt, shell commands ask, the sandbox is off."""
    policy = EffectivePolicy(
        agent=AgentId.CLAUDE_CODE,
        working_dirs=(WORKSPACE,),
        channels=(
            ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE),
            ChannelPolicy(Channel.SHELL_RECOGNIZED, Gate.NONE, Gate.NONE, sandboxed=True),
            ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.HUMAN, Gate.HUMAN, sandboxed=True),
        ),
    )
    return replace(policy, **changes)  # type: ignore[arg-type]


DENY_SSH = ReadRule("/home/a/.ssh/**", Gate.DENIED, FILE_RULES, SourceRef("settings.json", 7))


def test_without_rules_a_key_is_reachable_without_approval() -> None:
    result = reach_of(_claude_like(), KEY)
    assert result.reach is Reach.NO_APPROVAL
    assert result.via is not None
    assert result.via.channel.channel is Channel.FILE_TOOL


def test_a_deny_rule_with_an_unasked_shell_is_bypassable() -> None:
    policy = _claude_like(
        rules=(DENY_SSH,),
        channels=(
            ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE),
            ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.NONE, Gate.NONE),  # e.g. Bash(python:*)
        ),
    )
    result = reach_of(policy, KEY)
    assert result.reach is Reach.BYPASSABLE_RULE
    assert result.bypassed == DENY_SSH
    assert result.via is not None
    assert result.via.channel.channel is Channel.SHELL_ARBITRARY


def test_an_automated_approver_still_counts_as_a_bypass() -> None:
    policy = _claude_like(
        rules=(DENY_SSH,),
        channels=(
            ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE),
            ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.AUTOMATED, Gate.AUTOMATED),
        ),
    )
    assert reach_of(policy, KEY).reach is Reach.BYPASSABLE_RULE


def test_a_deny_rule_with_an_asking_shell_needs_an_approval() -> None:
    result = reach_of(_claude_like(rules=(DENY_SSH,)), KEY)
    assert result.reach is Reach.AFTER_APPROVAL
    assert result.bypassed == DENY_SSH  # the report can say the rule covers only some ways


def test_an_ask_rule_makes_the_file_tool_ask() -> None:
    ask = ReadRule("/home/a/.ssh/**", Gate.HUMAN, frozenset(Channel), None)
    policy = _claude_like(
        rules=(ask,), channels=(ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE),)
    )
    assert reach_of(policy, KEY).reach is Reach.AFTER_APPROVAL


def test_deny_beats_allow_wherever_it_is_written() -> None:
    allow = ReadRule("/home/a/**", Gate.NONE, frozenset(Channel))
    deny = ReadRule("/home/a/.ssh/**", Gate.DENIED, frozenset(Channel))
    policy = _claude_like(rules=(deny, allow))
    assert reach_of(policy, KEY).reach is Reach.BLOCKED_BY_RULE
    assert reach_of(replace(policy, rules=(allow, deny)), KEY).reach is Reach.BLOCKED_BY_RULE


def test_with_last_match_precedence_order_matters() -> None:
    allow = ReadRule("/home/a/**", Gate.NONE, frozenset(Channel))
    deny = ReadRule("/home/a/.ssh/**", Gate.DENIED, frozenset(Channel))
    policy = _claude_like(precedence=Precedence.LAST_MATCH, rules=(deny, allow))
    assert reach_of(policy, KEY).reach is Reach.NO_APPROVAL
    assert reach_of(replace(policy, rules=(allow, deny)), KEY).reach is Reach.BLOCKED_BY_RULE


def test_the_sandbox_closes_only_the_channels_it_applies_to() -> None:
    sandbox = SandboxPolicy(enabled=True, available=True, read_deny=("/home/a/.ssh",))
    policy = _claude_like(sandbox=sandbox)
    result = reach_of(policy, KEY)
    assert result.reach is Reach.NO_APPROVAL  # the file tool runs outside the sandbox
    assert result.via is not None
    assert result.via.channel.channel is Channel.FILE_TOOL


def test_sandbox_and_rules_together_block_every_channel() -> None:
    sandbox = SandboxPolicy(enabled=True, available=True, read_deny=("/home/a/.ssh",))
    result = reach_of(_claude_like(sandbox=sandbox, rules=(DENY_SSH,)), KEY)
    assert result.reach is Reach.BLOCKED_BY_RULE


def test_only_the_sandbox_blocking_is_blocked_by_sandbox() -> None:
    sandbox = SandboxPolicy(enabled=True, available=True, read_deny=("/home/a/.ssh",))
    policy = _claude_like(
        sandbox=sandbox,
        channels=(ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.NONE, Gate.NONE, sandboxed=True),),
    )
    assert reach_of(policy, KEY).reach is Reach.BLOCKED_BY_SANDBOX


def test_a_sandbox_that_cannot_run_here_protects_nothing() -> None:
    sandbox = SandboxPolicy(enabled=True, available=False, read_deny=("/home/a/.ssh",))
    policy = _claude_like(
        sandbox=sandbox,
        channels=(ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.NONE, Gate.NONE, sandboxed=True),),
    )
    assert reach_of(policy, KEY).reach is Reach.NO_APPROVAL


def test_a_read_only_allowlist_sandbox_refuses_everything_else() -> None:
    sandbox = SandboxPolicy(enabled=True, available=True, read_only=(WORKSPACE, "/usr"))
    policy = _claude_like(
        sandbox=sandbox,
        channels=(ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.NONE, Gate.NONE, sandboxed=True),),
    )
    assert reach_of(policy, KEY).reach is Reach.BLOCKED_BY_SANDBOX
    assert reach_of(policy, ENV).reach is Reach.NO_APPROVAL


def test_working_directories_decide_the_default_gate() -> None:
    policy = _claude_like(channels=(ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.HUMAN),))
    assert reach_of(policy, ENV).reach is Reach.NO_APPROVAL
    assert reach_of(policy, KEY).reach is Reach.AFTER_APPROVAL


def test_an_agent_without_known_channels_is_unknown() -> None:
    result = reach_of(EffectivePolicy(agent=AgentId.CURSOR), KEY)
    assert (result.reach, result.uncertain) == (Reach.UNKNOWN, True)


def test_unknown_settings_make_a_result_uncertain() -> None:
    result = reach_of(_claude_like(unknowns=("Manual mode and cat outside the workspace",)), KEY)
    assert result.reach is Reach.NO_APPROVAL
    assert result.uncertain
