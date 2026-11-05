"""Version control and registry credentials: GitHub CLI, git's credential store, netrc,
npm, PyPI and Cargo.

Present files are reported from ``stat``. With ``--deep`` each is parsed for the hosts or
registries it holds credentials for; tokens and passwords are dropped by the parsers in
:mod:`ifinjected.parsers.structure`.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected.homes import Platform, System
from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.presence import Refinement, each
from ifinjected.models import Evidence, Severity
from ifinjected.parsers.ini import ini_sections
from ifinjected.parsers.structure import (
    credential_store_hosts,
    netrc_machines,
    npmrc_registries_with_auth,
    top_level_keys,
    yaml_keys,
)


def gh_config_dir(p: Platform) -> Path:
    override = p._env_path("GH_CONFIG_DIR")
    if override is not None:
        return override
    if p.system is System.WINDOWS:
        return p.appdata / "GitHub CLI"
    return p.xdg_config_home / "gh"


def netrc_files(p: Platform) -> list[Path]:
    override = p._env_path("NETRC")
    if override is not None:
        return [override]
    files = [p.home / ".netrc"]
    if p.system is System.WINDOWS:
        files.append(p.home / "_netrc")
    return files


def npmrc_files(p: Platform, workspace: Path | None) -> list[Path]:
    files = [p._env_path("NPM_CONFIG_USERCONFIG") or p.home / ".npmrc"]
    if workspace is not None:
        files.append(workspace / ".npmrc")
    return files


def cargo_home(p: Platform) -> Path:
    return p._env_path("CARGO_HOME") or p.home / ".cargo"


def _gh_hosts(text: str) -> Refinement:
    keys = yaml_keys(text)
    hosts = top_level_keys(keys)
    plaintext = any(k.name == "oauth_token" and k.indent > 0 for k in keys)
    facts = (Evidence("gh", "hosts", ", ".join(hosts)),)
    if plaintext:
        return "GitHub CLI token (plain text)", Severity.HIGH, facts
    return "GitHub CLI login (token in the system keyring)", Severity.MEDIUM, facts


def _git_store(text: str) -> Refinement:
    hosts = credential_store_hosts(text)
    return "Git credential store", Severity.HIGH, (Evidence("git", "hosts", ", ".join(hosts)),)


def _netrc(text: str) -> Refinement:
    machines = netrc_machines(text)
    return "netrc passwords", Severity.HIGH, (Evidence("netrc", "machines", ", ".join(machines)),)


def _npmrc(text: str) -> Refinement:
    registries = npmrc_registries_with_auth(text)
    if not registries:
        return "npm config (no tokens)", Severity.LOW, ()
    return "npm token", Severity.HIGH, (Evidence("npm", "registries", ", ".join(registries)),)


def _pypirc(text: str) -> Refinement:
    sections = ini_sections(text)
    with_password = [s.name for s in sections if "password" in s.keys]
    if not with_password:
        return "PyPI config (no tokens)", Severity.LOW, ()
    return (
        "PyPI token",
        Severity.HIGH,
        (Evidence("pypi", "repositories", ", ".join(with_password)),),
    )


def collect_vcs(context: Context) -> Collected:
    p = context.platform
    found = Collected()
    found.extend(
        each(
            context,
            "gh.hosts",
            [gh_config_dir(p) / "hosts.yml"],
            title="GitHub CLI login",
            severity=Severity.MEDIUM,
            analyse=_gh_hosts,
        )
    )
    found.extend(
        each(
            context,
            "git.credentials",
            [p.home / ".git-credentials", p.xdg_config_home / "git" / "credentials"],
            title="Git credential store",
            severity=Severity.HIGH,
            analyse=_git_store,
        )
    )
    found.extend(
        each(
            context,
            "netrc",
            netrc_files(p),
            title="netrc passwords",
            severity=Severity.HIGH,
            analyse=_netrc,
        )
    )
    found.extend(
        each(
            context,
            "npm.token",
            npmrc_files(p, context.workspace),
            title="npm config (may hold a token)",
            severity=Severity.MEDIUM,
            analyse=_npmrc,
        )
    )
    found.extend(
        each(
            context,
            "pypi.token",
            [p.home / ".pypirc"],
            title="PyPI config (may hold a token)",
            severity=Severity.MEDIUM,
            analyse=_pypirc,
        )
    )
    cargo = cargo_home(p)
    found.extend(
        each(
            context,
            "cargo.token",
            [cargo / "credentials.toml", cargo / "credentials"],
            title="Cargo registry token",
            severity=Severity.HIGH,
        )
    )
    return found
