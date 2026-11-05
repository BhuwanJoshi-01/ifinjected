"""Prove mode: an open-only probe, run directly and under Codex's sandbox (IFJ-040, IFJ-041)."""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from ifinjected.models import AgentId, Policy, Reach, Snapshot
from ifinjected.orchestrator import diagnose, inspect_all
from ifinjected.prove.program import BEGIN, END, PROGRAM
from ifinjected.prove.runners import ProbeResult, parse, probe_argv, run_codex, run_direct
from ifinjected.prove.verdicts import judge
from ifinjected.runner import CommandResult, Outcome, SubprocessRunner
from tests.fakes import FakeRunner
from tests.homes import FakeMachine

_ALLOWED_CALLS = {
    "getattr", "os.open", "os.close", "socket.create_connection", "connection.close",
    "json.dumps", "sys.stdout.write", "host.rsplit", "target.rsplit", "int", "dict",
}  # fmt: skip


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    return "?"


def test_the_probe_only_opens_closes_and_connects() -> None:
    tree = ast.parse(PROGRAM)
    calls = {_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert calls <= _ALLOWED_CALLS, calls - _ALLOWED_CALLS
    assert "read" not in PROGRAM.replace("sys.stdout.write", "")
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imports == {"json", "os", "socket", "sys"}


def test_the_probe_opens_without_reading(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"x" * 10_000)
    missing = tmp_path / "missing"
    result = run_direct(SubprocessRunner(), [str(big), str(missing)], None, tmp_path)
    assert result.problem is None
    assert result.opened[str(big)] == 0
    assert result.opened[str(missing)] != 0


@pytest.mark.skipif(sys.platform == "win32", reason="FIFOs")
def test_a_fifo_does_not_block_the_probe(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = run_direct(SubprocessRunner(), [str(fifo)], None, tmp_path)
    assert result.problem is None
    assert str(fifo) in result.opened


def test_parse_rejects_garbage() -> None:
    assert parse("x", "nothing").problem == "the probe printed no answer"
    assert parse("x", f"{BEGIN}not json{END}").problem == "the probe's answer is not JSON"
    assert parse("x", f'{BEGIN}{{"protocol": 9}}{END}').problem == "unknown probe protocol"
    ok = parse("x", f'noise{BEGIN}{{"protocol": 1, "open": {{"/a": 0}}, "connect": 111}}{END}')
    assert (ok.opened, ok.connect) == ({"/a": 0}, 111)


def test_codex_runs_the_probe_with_codex_sandbox() -> None:
    fake = FakeRunner()
    argv = ("codex", "sandbox", "--", *probe_argv(["/k"], "example.com:443"))
    fake.script(*argv, stdout=f'{BEGIN}{{"protocol": 1, "open": {{"/k": 0}}, "connect": 101}}{END}')
    result = run_codex(fake, ["/k"], "example.com:443", None)
    assert (result.opened, result.connect, result.problem) == ({"/k": 0}, 101, None)
    missing = FakeRunner()
    missing.script_result(
        CommandResult(("codex", "sandbox", "--", *probe_argv(["/k"], None)), Outcome.NOT_FOUND)
    )
    assert run_codex(missing, ["/k"], None, None).problem == "codex is not installed"


def _snapshot(tmp_path: Path, config: str) -> Snapshot:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".codex/config.toml", config)
    return diagnose(inspect_all(machine.platform(), Policy(), machine.workspace))


def test_a_sandbox_that_opens_a_denied_file_is_contradicted(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, 'model = "x"\n')
    blocked = tuple(
        replace(e, reach=Reach.BLOCKED_BY_SANDBOX) if e.agent is AgentId.CODEX else e
        for e in snapshot.exposures
    )
    snapshot = replace(snapshot, exposures=blocked)
    key = next(e.path for e in snapshot.exposures if e.item == "ssh.key")
    direct, sandboxed = ProbeResult("direct", {key: 0}), ProbeResult("codex", {key: 0})
    _, findings = judge(snapshot, AgentId.CODEX, direct, sandboxed, None)
    assert [f.id for f in findings if f.item == "ssh.key"] == ["IFJ-PROVE-001"]
    refused = ProbeResult("codex", {key: 13})
    _, findings = judge(snapshot, AgentId.CODEX, direct, refused, None)
    assert findings == []


def test_reachable_and_opened_is_proven(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, 'model = "x"\n')
    key = next(e.path for e in snapshot.exposures if e.item == "ssh.key")
    _, findings = judge(
        snapshot,
        AgentId.CODEX,
        ProbeResult("direct", {key: 0}),
        ProbeResult("codex", {key: 0}),
        None,
    )
    assert [f.id for f in findings if f.item == "ssh.key"] == ["IFJ-PROVE-002"]


def test_a_connection_from_a_closed_sandbox_is_contradicted(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, 'model = "x"\n')
    _, findings = judge(
        snapshot,
        AgentId.CODEX,
        ProbeResult("direct"),
        ProbeResult("codex", connect=0),
        "example.com:443",
    )
    assert [f.id for f in findings] == ["IFJ-PROVE-003"]


def test_without_run_nothing_runs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.unit.test_cli import run_main

    assert run_main(monkeypatch, "prove") == 0
    assert "Nothing runs without --run" in capsys.readouterr().out
