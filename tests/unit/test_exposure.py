"""Every item for every agent: files, environment variables and sockets (IFJ-020, IFJ-021)."""

from __future__ import annotations

from pathlib import Path

from ifinjected.agents.claude_code import inspect_claude_code
from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import AgentId, Policy, Reach, SensitiveItem, Severity
from ifinjected.orchestrator import inspect_all
from ifinjected.policy.exposure import exposure_of, exposures
from ifinjected.policy.model import Channel, ChannelPolicy, EffectivePolicy, Gate, SandboxPolicy
from tests import canaries
from tests.homes import FakeMachine


def _item(item_id: str, path: str) -> SensitiveItem:
    return SensitiveItem(item_id, item_id, path, Severity.HIGH)


def _policy(*channels: ChannelPolicy, **changes: object) -> EffectivePolicy:
    return EffectivePolicy(agent=AgentId.CLAUDE_CODE, channels=channels, **changes)  # type: ignore[arg-type]


def test_environment_variables_are_as_reachable_as_the_easiest_shell() -> None:
    policy = _policy(
        ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE),
        ChannelPolicy(Channel.SHELL_RECOGNIZED, Gate.NONE, Gate.HUMAN),
        ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.HUMAN, Gate.HUMAN),
    )
    exposure = exposure_of(policy, _item("env.variables", ENVIRONMENT))
    assert (exposure.reach, exposure.channel) == (Reach.NO_APPROVAL, Channel.SHELL_RECOGNIZED)


def test_without_a_shell_the_environment_is_out_of_reach() -> None:
    policy = _policy(ChannelPolicy(Channel.FILE_TOOL, Gate.NONE, Gate.NONE))
    assert exposure_of(policy, _item("env.variables", ENVIRONMENT)).reach is Reach.UNKNOWN
    denied = _policy(ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.DENIED, Gate.DENIED))
    assert exposure_of(denied, _item("env.variables", ENVIRONMENT)).reach is Reach.BLOCKED_BY_RULE


def test_sockets_are_used_through_arbitrary_commands() -> None:
    policy = _policy(
        ChannelPolicy(Channel.SHELL_RECOGNIZED, Gate.NONE, Gate.NONE),
        ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.HUMAN, Gate.HUMAN),
    )
    exposure = exposure_of(policy, _item("socket.docker", "/var/run/docker.sock"))
    assert (exposure.reach, exposure.channel) == (Reach.AFTER_APPROVAL, Channel.SHELL_ARBITRARY)


def test_a_socket_behind_a_sandbox_is_uncertain() -> None:
    policy = _policy(
        ChannelPolicy(Channel.SHELL_ARBITRARY, Gate.NONE, Gate.NONE, sandboxed=True),
        sandbox=SandboxPolicy(enabled=True, available=True),
    )
    exposure = exposure_of(policy, _item("socket.ssh_agent", "/run/user/1000/ssh"))
    assert exposure.reach is Reach.NO_APPROVAL
    assert exposure.uncertain


def test_a_bypassed_rule_is_named_with_its_line(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    machine.write(
        ".claude/settings.json",
        {"permissions": {"allow": ["Bash(python3 *)"], "deny": ["Read(~/.ssh/**)"]}},
    )
    report = inspect_claude_code(machine.platform(), Policy(), machine.workspace)
    key = _item("ssh.key", str(machine.home / ".ssh" / "id_ed25519"))
    (exposure,) = exposures((report,), (key,))
    assert exposure.reach is Reach.BYPASSABLE_RULE
    assert exposure.bypassed is not None
    assert exposure.bypassed.line == 7
    assert exposure.bypassed_pattern == str(machine.home / ".ssh" / "**")


def test_agents_that_are_not_found_have_no_exposures(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    report = inspect_claude_code(machine.platform(), Policy(), machine.workspace)
    assert exposures((report,), (_item("x", "/x"),)) == ()


def test_a_whole_run_combines_inventory_and_agents_worst_first(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path, env={"OPENAI_API_KEY": canaries.OPENAI_KEY})
    machine.add_credentials()
    machine.write(".claude/settings.json", {"permissions": {"deny": ["Read(~/.aws/**)"]}})
    snapshot = inspect_all(machine.platform(), Policy(), machine.workspace)
    assert snapshot.items
    assert [a.agent for a in snapshot.agents] == [AgentId.CLAUDE_CODE]
    reaches = [e.reach for e in snapshot.exposures]
    assert reaches == sorted(reaches, key=lambda r: r.rank)
    by_item = {e.item: e for e in snapshot.exposures}
    assert by_item["env.variables"].reach is Reach.NO_APPROVAL  # echo $OPENAI_API_KEY
    assert by_item["ssh.key"].reach is Reach.NO_APPROVAL  # cat ~/.ssh/id_ed25519
    assert by_item["aws.credentials"].reach is Reach.AFTER_APPROVAL  # deny rule, asking shell
    assert canaries.MARK not in repr(snapshot)
