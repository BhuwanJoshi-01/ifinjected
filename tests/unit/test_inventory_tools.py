"""Developer service tokens, password managers and browser sessions (IFJ-014)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.files import Level, recording
from ifinjected.homes import System
from ifinjected.inventory.base import Context
from ifinjected.inventory.catalog import load_catalog
from ifinjected.inventory.tools import (
    chromium_user_data_dirs,
    collect_tools,
    firefox_profiles_dir,
    huggingface_token_file,
    terraform_credentials_file,
)
from ifinjected.models import Policy, Severity
from tests.homes import FakeMachine


def _items(machine: FakeMachine) -> list[tuple[str, str, Severity]]:
    found = collect_tools(Context(platform=machine.platform(), policy=Policy()))
    return sorted((i.id, i.title, i.severity) for i in found.items)


def test_nothing_on_a_clean_machine(tmp_path: Path) -> None:
    assert _items(FakeMachine(tmp_path)) == []


def test_developer_service_tokens(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    p = machine.platform()
    machine.write_at(huggingface_token_file(p), "hf_x")
    machine.write(".supabase/access-token", "sbp_x")
    machine.write_at(terraform_credentials_file(p), "{}")
    machine.write(".vault-token", "hvs.x")
    assert [item[0] for item in _items(machine)] == [
        "huggingface.token",
        "supabase.token",
        "terraform.token",
        "vault.token",
    ]


def test_hugging_face_honours_its_variables(tmp_path: Path) -> None:
    default = FakeMachine(tmp_path).platform()
    assert huggingface_token_file(default) == default.home / ".cache/huggingface/token"
    hf_home = FakeMachine(tmp_path, env={"HF_HOME": "/hf"}).platform()
    assert huggingface_token_file(hf_home) == Path("/hf/token")
    explicit = FakeMachine(tmp_path, env={"HF_TOKEN_PATH": "/t", "HF_HOME": "/hf"}).platform()
    assert huggingface_token_file(explicit) == Path("/t")
    xdg = FakeMachine(tmp_path, env={"XDG_CACHE_HOME": "/c"}).platform()
    assert huggingface_token_file(xdg) == Path("/c/huggingface/token")


def test_password_managers_are_directories(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    (machine.home / ".password-store").mkdir(parents=True)
    (machine.home / ".config" / "op").mkdir(parents=True)
    assert [item[0] for item in _items(machine)] == ["onepassword.cli", "pass.store"]


def test_browser_cookies_per_profile_without_opening_them(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    p = machine.platform()
    chrome = dict(chromium_user_data_dirs(p))["Chrome"]
    machine.write_at(chrome / "Default" / "Network" / "Cookies", b"SQLite format 3\x00")
    machine.write_at(chrome / "Profile 2" / "Cookies", b"SQLite format 3\x00")
    machine.write_at(chrome / "Local State", "{}")
    (chrome / "Crashpad").mkdir()
    firefox = firefox_profiles_dir(p)
    machine.write_at(firefox / "abcd.default-release" / "cookies.sqlite", b"SQLite format 3\x00")
    machine.write_at(firefox / "profiles.ini", "[General]\n")
    with recording() as ledger:
        items = _items(machine)
    assert items == [
        (
            "browser.cookies",
            "Chrome session cookies (encrypted with a key you can read)",
            Severity.MEDIUM,
        ),
        (
            "browser.cookies",
            "Chrome session cookies (encrypted with a key you can read)",
            Severity.MEDIUM,
        ),
        ("browser.cookies", "Firefox session cookies (not encrypted)", Severity.HIGH),
    ]
    assert {a.level for a in ledger.accesses} == {Level.STAT}


@pytest.mark.parametrize(
    ("system", "chrome_parts", "firefox_parts"),
    [
        (System.LINUX, (".config", "google-chrome"), (".mozilla", "firefox")),
        (
            System.MACOS,
            ("Library", "Application Support", "Google", "Chrome"),
            ("Library", "Application Support", "Firefox", "Profiles"),
        ),
        (
            System.WINDOWS,
            ("AppData", "Local", "Google", "Chrome", "User Data"),
            ("AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
        ),
    ],
)
def test_browser_locations_per_system(
    tmp_path: Path, system: System, chrome_parts: tuple[str, ...], firefox_parts: tuple[str, ...]
) -> None:
    p = FakeMachine(tmp_path, system).platform()
    if system is System.WINDOWS:
        p = FakeMachine(
            tmp_path, system, env={"LOCALAPPDATA": str(p.home / "AppData" / "Local")}
        ).platform()
    assert dict(chromium_user_data_dirs(p))["Chrome"] == p.home.joinpath(*chrome_parts)
    assert firefox_profiles_dir(p) == p.home.joinpath(*firefox_parts)


def test_terraform_on_windows_lives_in_appdata(tmp_path: Path) -> None:
    p = FakeMachine(tmp_path, System.WINDOWS).platform()
    assert terraform_credentials_file(p) == p.appdata / "terraform.d" / "credentials.tfrc.json"


def test_every_look_is_declared(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    p = machine.platform()
    chrome = dict(chromium_user_data_dirs(p))["Chrome"]
    machine.write_at(chrome / "Default" / "Cookies", b"x")
    machine.write_at(firefox_profiles_dir(p) / "x.default" / "cookies.sqlite", b"x")
    machine.write_at(huggingface_token_file(p), "x")
    (machine.home / ".password-store").mkdir()
    catalog = load_catalog()
    with recording() as ledger:
        collect_tools(Context(platform=p, policy=Policy()))
    for access in ledger.accesses:
        assert catalog.declared_level(Path(access.path), p, None) is not None, access.path
