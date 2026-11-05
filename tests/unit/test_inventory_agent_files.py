"""Agents' own tokens and transcripts, and .env files near the work (IFJ-015)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.files import Level, recording
from ifinjected.inventory.agent_files import collect_agent_files, env_directories
from ifinjected.inventory.base import Context
from ifinjected.inventory.catalog import load_catalog
from ifinjected.models import Policy, Severity
from ifinjected.parsers.dotenv import dotenv_names, is_env_file
from tests import canaries
from tests.homes import FakeMachine


def _context(machine: FakeMachine, include_env: bool = False) -> Context:
    return Context(
        platform=machine.platform(),
        policy=Policy(include_env=include_env),
        workspace=machine.workspace,
    )


def test_every_agents_login_token_is_found(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".claude/.credentials.json", "{}")
    machine.write(".codex/auth.json", "{}")
    machine.write(".gemini/oauth_creds.json", "{}")
    machine.write(".local/share/opencode/auth.json", "{}")
    machine.write(".copilot/providers.json", "{}")
    machine.workspace.mkdir(parents=True)
    found = collect_agent_files(_context(machine))
    tokens = sorted(i.title for i in found.items if i.id == "agent.auth")
    assert tokens == [
        "Claude Code login token",
        "Codex login token",
        "Copilot CLI login token",
        "Gemini CLI login token",
        "opencode login token",
    ]
    assert all(i.severity is Severity.HIGH for i in found.items if i.id == "agent.auth")


def test_transcripts_and_history_are_medium(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    (machine.home / ".claude" / "projects").mkdir(parents=True)
    machine.write(".claude/history.jsonl", "{}\n")
    (machine.home / ".codex" / "sessions").mkdir(parents=True)
    found = collect_agent_files(Context(platform=machine.platform(), policy=Policy()))
    assert sorted(i.title for i in found.items) == [
        "Claude Code prompt history (may hold secrets from earlier sessions)",
        "Claude Code transcripts (may hold secrets from earlier sessions)",
        "Codex transcripts (may hold secrets from earlier sessions)",
    ]


def test_env_files_in_the_workspace_subdirectories_and_parents(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write_workspace(".env", f"KEY={canaries.ENV_VALUE}\n")
    machine.write_workspace(".env.local", "X=1\n")
    machine.write_workspace(".env.example", "KEY=\n")
    machine.write_workspace("apps/web/.env", "A=1\n")
    machine.write_workspace("node_modules/pkg/.env", "B=1\n")
    machine.write("src/.env.production", "C=1\n")
    found = collect_agent_files(_context(machine))
    paths = sorted(Path(i.path).relative_to(machine.home).as_posix() for i in found.items)
    # apps/web is two levels down and node_modules is skipped; .env.example is a template.
    assert paths == ["src/.env.production", "src/app/.env", "src/app/.env.local"]
    titles = {Path(i.path).name: i.title for i in found.items}
    assert titles[".env.production"] == ".env file above the workspace"
    assert canaries.MARK not in repr(found)


def test_only_direct_subdirectories_are_searched(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write_workspace("apps/.env", "A=1\n")
    machine.write_workspace("apps/web/.env", "B=1\n")
    found = collect_agent_files(_context(machine))
    assert [Path(i.path).parent.name for i in found.items] == ["apps"]


def test_include_env_lists_names_and_never_values(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    with recording() as ledger:
        found = collect_agent_files(_context(machine, include_env=True))
    env = next(i for i in found.items if i.id == "env.file")
    assert env.fact("variables") == "OPENAI_API_KEY, APP_SECRET"
    assert canaries.MARK not in repr(found)
    assert any(a.level is Level.FULL for a in ledger.accesses)


def test_without_include_env_files_are_only_stated(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    with recording() as ledger:
        collect_agent_files(_context(machine))
    assert {a.level for a in ledger.accesses} == {Level.STAT}


def test_parents_stop_at_the_home_directory(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.workspace.mkdir(parents=True)
    directories = env_directories(machine.platform(), machine.workspace)
    assert directories[-1] == machine.home
    assert machine.home.parent not in directories


@pytest.mark.parametrize("include_env", [False, True])
def test_every_look_is_declared(tmp_path: Path, include_env: bool) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write_workspace("apps/web/.env", "A=1\n")
    machine.write(".claude/.credentials.json", "{}")
    (machine.home / ".claude" / "projects").mkdir(parents=True)
    p = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        collect_agent_files(_context(machine, include_env=include_env))
    for access in ledger.accesses:
        declared = catalog.declared_level(
            Path(access.path), p, machine.workspace, include_env=include_env
        )
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (".env", True),
        (".env.local", True),
        (".env.production.local", True),
        (".env.example", False),
        (".env.sample", False),
        (".env.template", False),
        (".envrc", False),
        ("env", False),
    ],
)
def test_which_names_are_env_files(name: str, expected: bool) -> None:
    assert is_env_file(name) is expected


def test_dotenv_names_only() -> None:
    assert dotenv_names(f"export A=1\nB='{canaries.ENV_VALUE}'\n# C=2\n") == ("A", "B")
