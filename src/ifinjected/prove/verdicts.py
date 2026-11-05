"""What the probe says about the configuration's claims: proven or contradicted."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from ifinjected.inventory.environment import ENVIRONMENT
from ifinjected.models import (
    AgentId,
    Confidence,
    Finding,
    Reach,
    Severity,
    Snapshot,
    SourceRef,
    Status,
)
from ifinjected.policy.model import Network
from ifinjected.prove.runners import ProbeResult
from ifinjected.rules.engine import Registry

registry = Registry()
_SOCKETS = {"socket.ssh_agent", "socket.docker", "socket.gpg_agent"}


@registry.rule(
    "IFJ-PROVE-001", "The sandbox opened what the configuration denies", max_status=Status.FAIL
)
def _contradicted(snapshot: object) -> Iterator[Finding]:
    """``prove --run`` ran the probe under the agent's own sandbox, and it opened a file
    the agent's configuration says the sandbox refuses. The protection is not there:
    check the sandbox's version, the platform it runs on, and the settings it really
    reads."""
    yield from ()


@registry.rule("IFJ-PROVE-002", "Proven: the sandbox opens this credential", max_status=Status.WARN)
def _proven(snapshot: object) -> Iterator[Finding]:
    """The probe, run under the agent's own sandbox, opened the credential the
    configuration says it can reach: the finding is not a reading of documentation but
    an observation on this machine. Only the open is attempted; nothing is read."""
    yield from ()


@registry.rule("IFJ-PROVE-003", "A sandboxed command reached the network", max_status=Status.FAIL)
def _network(snapshot: object) -> Iterator[Finding]:
    """With ``--network``, the probe connected to the target from inside a sandbox whose
    configuration closes the network. Data could leave the same way."""
    yield from ()


@dataclass(frozen=True, slots=True)
class Probed:
    path: str
    item: str
    title: str
    claimed: Reach
    direct: int | None
    sandboxed: int | None


def probe_paths(snapshot: Snapshot, agent: AgentId) -> list[tuple[str, str, str, Reach]]:
    """(path, item id, title, claimed reach) of the files worth probing for ``agent``."""
    titles = {(i.id, i.path): i.title for i in snapshot.items}
    found = []
    for exposure in snapshot.exposures:
        if exposure.agent is not agent or exposure.path == ENVIRONMENT or exposure.item in _SOCKETS:
            continue
        found.append(
            (
                exposure.path,
                exposure.item,
                titles.get((exposure.item, exposure.path), exposure.item),
                exposure.reach,
            )
        )
    return found


def judge(
    snapshot: Snapshot,
    agent: AgentId,
    direct: ProbeResult,
    sandboxed: ProbeResult,
    network_target: str | None,
) -> tuple[list[Probed], list[Finding]]:
    rows: list[Probed] = []
    findings: list[Finding] = []
    for path, item, title, claimed in probe_paths(snapshot, agent):
        base = direct.opened.get(path)
        under = sandboxed.opened.get(path)
        rows.append(Probed(path, item, title, claimed, base, under))
        if base != 0 or under is None:
            continue  # not openable at all, or not probed
        if under == 0 and claimed is Reach.BLOCKED_BY_SANDBOX:
            findings.append(
                Finding(
                    "IFJ-PROVE-001",
                    Status.FAIL,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"{agent.display_name}'s sandbox opened {title}, which its configuration "
                    "denies",
                    f"The probe opened {path} under {sandboxed.runner} sandbox.",
                    agent=agent,
                    item=item,
                    sources=(SourceRef(path),),
                    recommended_action="Check that the sandbox really reads the settings you "
                    "changed.",
                    verify_command="ifinjected prove --run",
                )
            )
        elif under == 0 and claimed.reachable:
            findings.append(
                Finding(
                    "IFJ-PROVE-002",
                    Status.WARN,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"Proven: {agent.display_name}'s sandbox opens {title}",
                    f"The probe opened {path} under {sandboxed.runner} sandbox, as the "
                    "configuration says.",
                    agent=agent,
                    item=item,
                    sources=(SourceRef(path),),
                    recommended_action="Deny the directory in the agent's sandbox (ifinjected "
                    "plan shows how).",
                    verify_command="ifinjected prove --run",
                )
            )
    policy = next((a.policy for a in snapshot.agents if a.agent is agent and a.policy), None)
    if (
        network_target
        and sandboxed.connect == 0
        and policy is not None
        and policy.sandbox.network is Network.NONE
    ):
        findings.append(
            Finding(
                "IFJ-PROVE-003",
                Status.FAIL,
                Severity.HIGH,
                Confidence.HIGH,
                f"A command in {agent.display_name}'s sandbox connected to {network_target}",
                "The configuration closes the sandbox's network, but the connection succeeded.",
                agent=agent,
                verify_command="ifinjected prove --run --network",
            )
        )
    return rows, findings
