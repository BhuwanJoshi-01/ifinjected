"""Running the probe directly and under each agent's own sandbox, and reading its answer.

``direct`` runs the probe with your rights: the baseline (what any process can open).
``codex`` runs it with ``codex sandbox --``, which applies your effective Codex policy.
An agent whose sandbox cannot be run from outside (Claude Code's is embedded; Copilot
CLI's is not exposed) stays *claimed, not proven*.

Nothing runs unless ``prove --run`` asks for it; every command goes through the bounded
runner (no shell, a timeout, capped output).
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ifinjected.prove.program import BEGIN, END, PROGRAM
from ifinjected.runner import CommandRunner

TIMEOUT = 60.0


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one runner saw: errno per path (0: opened), the connection result, or why it
    produced nothing."""

    runner: str
    opened: dict[str, int] = field(default_factory=dict)
    connect: int | None = None
    problem: str | None = None


def probe_argv(paths: list[str], connect: str | None) -> list[str]:
    args = [sys.executable, "-I", "-c", PROGRAM]
    if connect is not None:
        args += ["--connect", connect]
    return [*args, *paths]


def parse(runner: str, stdout: str) -> ProbeResult:
    start, end = stdout.rfind(BEGIN), stdout.rfind(END)
    if start == -1 or end <= start:
        return ProbeResult(runner, problem="the probe printed no answer")
    try:
        data = json.loads(stdout[start + len(BEGIN) : end])
    except ValueError:
        return ProbeResult(runner, problem="the probe's answer is not JSON")
    if not isinstance(data, dict) or data.get("protocol") != 1:
        return ProbeResult(runner, problem="unknown probe protocol")
    opened = {str(k): int(v) for k, v in dict(data.get("open", {})).items()}
    connect = data.get("connect")
    return ProbeResult(runner, opened, connect if isinstance(connect, int) else None)


def run_direct(
    runner: CommandRunner, paths: list[str], connect: str | None, cwd: Path | None
) -> ProbeResult:
    result = runner.run(probe_argv(paths, connect), timeout=TIMEOUT, cwd=cwd)
    if not result.ok:
        return ProbeResult("direct", problem=f"the probe exited with {result.returncode}")
    return parse("direct", result.stdout)


def codex_available() -> bool:
    return shutil.which("codex") is not None


def run_codex(
    runner: CommandRunner, paths: list[str], connect: str | None, cwd: Path | None
) -> ProbeResult:
    """The probe under ``codex sandbox``, with the user's effective Codex policy."""
    argv = ["codex", "sandbox", "--", *probe_argv(paths, connect)]
    result = runner.run(argv, timeout=TIMEOUT, cwd=cwd)
    if result.outcome.value == "not_found":
        return ProbeResult("codex", problem="codex is not installed")
    parsed = parse("codex", result.stdout)
    if parsed.problem is not None and not result.ok:
        detail = (result.stderr.strip().splitlines() or [""])[0][:160]
        return ProbeResult(
            "codex", problem=f"codex sandbox exited with {result.returncode}: {detail}"
        )
    return parsed
