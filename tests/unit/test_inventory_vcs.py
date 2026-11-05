"""Version control, registry, Docker and Kubernetes credentials (IFJ-012, IFJ-013)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.files import Level, recording
from ifinjected.homes import System
from ifinjected.inventory import collect_inventory
from ifinjected.inventory.base import Context
from ifinjected.inventory.catalog import load_catalog
from ifinjected.inventory.containers import collect_containers, kubeconfig_files
from ifinjected.inventory.vcs import collect_vcs, gh_config_dir, netrc_files
from ifinjected.models import Policy, SensitiveItem, Severity
from ifinjected.parsers.structure import (
    credential_store_hosts,
    docker_auth,
    netrc_machines,
    npmrc_registries_with_auth,
    top_level_keys,
    yaml_keys,
)
from tests import canaries
from tests.homes import FakeMachine


def _items(machine: FakeMachine, deep: bool) -> dict[str, SensitiveItem]:
    context = Context(platform=machine.platform(), policy=Policy(deep=deep))
    found = collect_vcs(context)
    found.extend(collect_containers(context))
    return {i.id: i for i in found.items}


def test_without_deep_files_are_only_stated(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    with recording() as ledger:
        items = _items(machine, deep=False)
    assert set(items) == {
        "gh.hosts",
        "netrc",
        "npm.token",
        "pypi.token",
        "docker.config",
        "kube.config",
    }
    assert {a.level for a in ledger.accesses} == {Level.STAT}
    assert items["npm.token"].title == "npm config (may hold a token)"


def test_deep_names_hosts_and_registries_and_keeps_no_value(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".git-credentials", f"https://alice:{canaries.GH_TOKEN}@github.com\n")
    items = _items(machine, deep=True)
    assert items["gh.hosts"].title == "GitHub CLI token (plain text)"
    assert items["gh.hosts"].fact("hosts") == "github.com"
    assert items["git.credentials"].fact("hosts") == "github.com"
    assert items["netrc"].fact("machines") == "api.example.com"
    assert items["npm.token"].fact("registries") == "//registry.npmjs.org/"
    assert items["pypi.token"].fact("repositories") == "pypi"
    assert items["docker.config"].title == "Docker registry passwords (plain text)"
    assert items["docker.config"].fact("inline_registries") == "ghcr.io"
    assert items["kube.config"].fact("credentials") == "tokens"
    assert canaries.MARK not in repr(items)


def test_a_gh_login_in_the_keyring_is_medium(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".config/gh/hosts.yml", "github.com:\n    user: alice\n    git_protocol: ssh\n")
    item = _items(machine, deep=True)["gh.hosts"]
    assert (item.title, item.severity) == (
        "GitHub CLI login (token in the system keyring)",
        Severity.MEDIUM,
    )


def test_docker_with_a_credential_store_is_medium(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".docker/config.json", {"auths": {"ghcr.io": {}}, "credsStore": "desktop"})
    item = _items(machine, deep=True)["docker.config"]
    assert (item.severity, item.fact("credential_store")) == (Severity.MEDIUM, "desktop")


def test_a_kubeconfig_with_an_exec_plugin_is_medium(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(
        ".kube/config",
        "users:\n- name: eks\n  user:\n    exec:\n      command: aws\n"
        "      args: [eks, get-token]\n",
    )
    item = _items(machine, deep=True)["kube.config"]
    assert (item.severity, item.fact("plugins")) == (Severity.MEDIUM, "exec plugins")


def test_npm_and_pypi_configs_without_tokens_are_low(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".npmrc", "registry=https://registry.npmjs.org/\nsave-exact=true\n")
    machine.write(".pypirc", "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\n")
    items = _items(machine, deep=True)
    assert items["npm.token"].severity is Severity.LOW
    assert items["pypi.token"].severity is Severity.LOW


def test_a_project_npmrc_is_found_in_the_workspace(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write_workspace(".npmrc", f"//npm.pkg.github.com/:_authToken={canaries.GH_TOKEN}\n")
    context = Context(
        platform=machine.platform(), policy=Policy(deep=True), workspace=machine.workspace
    )
    found = collect_vcs(context)
    assert [i.fact("registries") for i in found.items] == ["//npm.pkg.github.com/"]


def test_cargo_credentials(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(".cargo/credentials.toml", '[registry]\ntoken = "x"\n')
    assert _items(machine, deep=False)["cargo.token"].severity is Severity.HIGH


def test_overrides_and_windows_locations(tmp_path: Path) -> None:
    windows = FakeMachine(tmp_path, System.WINDOWS).platform()
    assert gh_config_dir(windows) == windows.appdata / "GitHub CLI"
    assert netrc_files(windows) == [windows.home / ".netrc", windows.home / "_netrc"]
    linux = FakeMachine(tmp_path, env={"KUBECONFIG": "/a/one:/b/two", "GH_CONFIG_DIR": "/gh"})
    assert kubeconfig_files(linux.platform()) == [Path("/a/one"), Path("/b/two")]
    assert gh_config_dir(linux.platform()) == Path("/gh")
    win_kube = FakeMachine(tmp_path, System.WINDOWS, env={"KUBECONFIG": "C:\\a;C:\\b"})
    assert len(kubeconfig_files(win_kube.platform())) == 2


@pytest.mark.parametrize("deep", [False, True])
def test_the_whole_inventory_looks_only_where_the_catalog_says(tmp_path: Path, deep: bool) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".git-credentials", "https://x@github.com\n")
    machine.write(".cargo/credentials.toml", "")
    platform = machine.platform()
    catalog = load_catalog()
    order = list(Level)
    with recording() as ledger:
        found = collect_inventory(
            Context(platform=platform, policy=Policy(deep=deep), workspace=machine.workspace)
        )
    assert found.items
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, machine.workspace, deep=deep)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access
    assert canaries.MARK not in repr(found)


# --- the structure parsers ------------------------------------------------------------------


def test_yaml_keys_keep_names_and_indentation_only() -> None:
    keys = yaml_keys(
        "github.com:\n    oauth_token: gho_x\n    user: alice\n# c\nenterprise.example:\n"
        "users:\n- name: dev\n  user:\n    token: abc\n"
    )
    assert top_level_keys(keys) == ("github.com", "enterprise.example", "users")
    assert ("oauth_token", 4) in {(k.name, k.indent) for k in keys}
    assert "gho_x" not in repr(keys)
    assert "abc" not in repr(keys)


def test_credential_store_hosts() -> None:
    text = "https://alice:tok@github.com\nhttps://gitlab.example.org/x\nnot a url\nhttps://[bad\n"
    assert credential_store_hosts(text) == ("github.com", "gitlab.example.org")


def test_netrc_machines() -> None:
    assert netrc_machines("machine a.org login x password y\nmachine b.org\ndefault login z") == (
        "a.org",
        "b.org",
        "default",
    )


def test_npmrc_registries_with_auth() -> None:
    text = (
        "//registry.npmjs.org/:_authToken=npm_x\n"
        "//npm.pkg.github.com/:username=alice\n"
        "_auth=dXNlcjpwYXNz\nregistry=https://registry.npmjs.org/\n"
    )
    assert npmrc_registries_with_auth(text) == ("//registry.npmjs.org/", "default")


def test_docker_auth_shapes() -> None:
    auth = docker_auth(
        '{"auths": {"a.io": {"auth": "eA=="}, "b.io": {}}, "credHelpers": {"c": "ecr-login"}}'
    )
    assert auth is not None
    assert (auth.inline, auth.store, auth.helpers) == (("a.io",), None, ("ecr-login",))
    assert docker_auth("not json") is None
    assert docker_auth("[1, 2]") is None
