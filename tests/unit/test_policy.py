"""The workspace policy file, .ifinjected.toml (IFJ-006)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.config import PolicyError, apply_overrides, load_policy, parse_policy
from ifinjected.models import DEFAULT_LEVELS, AgentId, Family, Policy, PolicyLevel
from tests.fakes import read_fixture


def _parse(text: str, source: str = ".ifinjected.toml") -> Policy:
    return parse_policy(text, source)


def test_no_settings_means_the_defaults() -> None:
    assert _parse("schema_version = 1\n") == Policy(source=".ifinjected.toml")


def test_the_defaults_fail_strict_only_on_what_really_matters() -> None:
    policy = Policy()
    denied = {family for family in Family if policy.level(family) is PolicyLevel.DENY}
    assert denied == {Family.READ, Family.TRIFECTA, Family.PROVE, Family.DIFF}
    assert policy.deep is False  # structure of credential files is opt-in
    assert policy.include_env is False  # .env variable names are opt-in
    assert policy.agents == ()


def test_every_key() -> None:
    policy = _parse(read_fixture("policy", "complete.toml"), "repo/.ifinjected.toml")
    levels = dict(DEFAULT_LEVELS)
    levels.update(
        {
            Family.SECRET: PolicyLevel.DENY,
            Family.READ: PolicyLevel.WARN,
            Family.MCP: PolicyLevel.ALLOW,
        }
    )
    assert policy == Policy(
        agents=(AgentId.CLAUDE_CODE, AgentId.CODEX),
        deep=True,
        include_env=True,
        max_file_bytes=65536,
        levels=tuple(levels.items()),
        accept_items=("ssh.key", "gh.hosts"),
        accept_mcp_servers=("github", "context7"),
        accept_hosts=("github.com", "*.pypi.org"),
        source="repo/.ifinjected.toml",
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "schema_version"),
        ("schema_version = '1'\n", "schema_version must be the number 1"),
        ("schema_version = 2\n", "schema_version 2 is not supported"),
        ("schema_version = 1\n[scan]\ndeep = 'yes'\n", "scan.deep must be true or false"),
        ("schema_version = 1\n[scan]\nagents = []\n", "scan.agents must be a list of agents"),
        ("schema_version = 1\n[scan]\nagents = ['aider']\n", "'aider' is not an agent"),
        ("schema_version = 1\n[scan]\nmax_file_bytes = 0\n", "scan.max_file_bytes"),
        ("schema_version = 1\n[scan]\nmax_file_bytes = true\n", "scan.max_file_bytes"),
        (
            "schema_version = 1\n[policy]\nread = 'maybe'\n",
            "policy.read must be one of allow, warn, deny",
        ),
        ("schema_version = 1\n[policy]\nsecrets = 'warn'\n", "unknown key policy.secrets"),
        ("schema_version = 1\n[accept]\nitems = 'ssh.key'\n", "accept.items must be a list"),
        ("schema_version = 1\n[accept]\nitems = ['../etc']\n", "accept.items must be a list"),
        ("schema_version = 1\n[accept]\nhosts = ['https://x']\n", "accept.hosts must be a list"),
        ("schema_version = 1\n[allow]\nports = [1]\n", r"unknown section \[allow\]"),
        ("schema_version = 1\nscan = 1\n", "scan must be a section"),
        ("schema_version = 1\nstrict = true\n", "unknown key strict"),
        ("schema_version = 1\n[scan\n", "is not valid TOML"),
    ],
)
def test_anything_unexpected_is_an_error_naming_the_key(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message) as error:
        _parse(text, "repo/.ifinjected.toml")
    assert str(error.value).startswith("repo/.ifinjected.toml")


def test_a_long_bad_value_is_shortened_in_the_message() -> None:
    with pytest.raises(PolicyError) as error:
        _parse(f"schema_version = 1\n[scan]\ndeep = '{'x' * 200}'\n")
    assert "x" * 60 not in str(error.value)


def test_duplicate_names_are_kept_once_in_order() -> None:
    policy = _parse(
        "schema_version = 1\n[scan]\nagents = ['codex', 'codex', 'cursor']\n"
        "[accept]\nhosts = ['b.org', 'a.org', 'b.org']\n"
    )
    assert policy.agents == (AgentId.CODEX, AgentId.CURSOR)
    assert policy.accept_hosts == ("b.org", "a.org")


def test_a_workspace_without_a_file_has_the_defaults(tmp_path: Path) -> None:
    assert load_policy(tmp_path) == Policy()


def test_the_file_is_read_from_the_workspace(tmp_path: Path) -> None:
    (tmp_path / ".ifinjected.toml").write_text(
        "schema_version = 1\n[scan]\ndeep = true\n", encoding="utf-8"
    )
    policy = load_policy(tmp_path)
    assert policy.deep is True
    assert policy.source == str(tmp_path / ".ifinjected.toml")


def test_a_policy_link_out_of_the_workspace_is_refused(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (tmp_path / "elsewhere.toml").write_text("schema_version = 1\n", encoding="utf-8")
    try:
        (workspace / ".ifinjected.toml").symlink_to(tmp_path / "elsewhere.toml")
    except OSError:
        pytest.skip("symbolic links are not available")
    with pytest.raises(PolicyError, match="outside the workspace"):
        load_policy(workspace)


def test_an_oversized_policy_is_refused(tmp_path: Path) -> None:
    (tmp_path / ".ifinjected.toml").write_text("#" * 70_000, encoding="utf-8")
    with pytest.raises(PolicyError, match="larger than"):
        load_policy(tmp_path)


def test_flags_override_the_file_and_none_keeps_it() -> None:
    policy = _parse("schema_version = 1\n[scan]\ndeep = true\n")
    assert apply_overrides(policy) is policy
    changed = apply_overrides(policy, agents=(AgentId.GEMINI_CLI,), deep=False, include_env=True)
    assert (changed.agents, changed.deep, changed.include_env) == (
        (AgentId.GEMINI_CLI,),
        False,
        True,
    )
