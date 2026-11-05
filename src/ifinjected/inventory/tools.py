"""Tokens of developer services, password managers and browser sessions.

Developer CLIs (Hugging Face, Supabase, Terraform, Vault) keep long-lived tokens in
well-known files. Password managers are reported where they can be used without a new
prompt. Browsers keep session cookies per profile: whoever can copy the cookie database
can often act as you on every site you are signed in to. All of it is found with
``stat`` and directory listings only.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected.files import Kind, list_directory, stat_entry
from ifinjected.homes import Platform, System
from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.presence import present
from ifinjected.models import Evidence, SensitiveItem, Severity


def huggingface_token_file(p: Platform) -> Path:
    explicit = p._env_path("HF_TOKEN_PATH")
    if explicit is not None:
        return explicit
    home = p._env_path("HF_HOME") or p.xdg_cache_home / "huggingface"
    return home / "token"


def terraform_credentials_file(p: Platform) -> Path:
    if p.system is System.WINDOWS:
        return p.appdata / "terraform.d" / "credentials.tfrc.json"
    return p.home / ".terraform.d" / "credentials.tfrc.json"


def password_store_dir(p: Platform) -> Path:
    return p._env_path("PASSWORD_STORE_DIR") or p.home / ".password-store"


def chromium_user_data_dirs(p: Platform) -> list[tuple[str, Path]]:
    """(browser, user data directory) for Chrome and Chromium on this system."""
    if p.system is System.MACOS:
        support = p.home / "Library" / "Application Support"
        return [("Chrome", support / "Google" / "Chrome"), ("Chromium", support / "Chromium")]
    if p.system is System.WINDOWS:
        local = p.localappdata
        return [
            ("Chrome", local / "Google" / "Chrome" / "User Data"),
            ("Chromium", local / "Chromium" / "User Data"),
        ]
    config = p.xdg_config_home
    return [("Chrome", config / "google-chrome"), ("Chromium", config / "chromium")]


def firefox_profiles_dir(p: Platform) -> Path:
    if p.system is System.MACOS:
        return p.home / "Library" / "Application Support" / "Firefox" / "Profiles"
    if p.system is System.WINDOWS:
        return p.appdata / "Mozilla" / "Firefox" / "Profiles"
    return p.home / ".mozilla" / "firefox"


def collect_tools(context: Context) -> Collected:
    p = context.platform
    found = present(
        "huggingface.token",
        [huggingface_token_file(p)],
        title="Hugging Face token",
        severity=Severity.HIGH,
    )
    found.extend(
        present(
            "supabase.token",
            [p.home / ".supabase" / "access-token"],
            title="Supabase access token (plain text)",
            severity=Severity.HIGH,
        )
    )
    found.extend(
        present(
            "terraform.token",
            [terraform_credentials_file(p)],
            title="Terraform Cloud token (plain text)",
            severity=Severity.HIGH,
        )
    )
    found.extend(
        present(
            "vault.token", [p.home / ".vault-token"], title="Vault token", severity=Severity.HIGH
        )
    )
    found.extend(_password_managers(p))
    found.extend(_browsers(p))
    return found


def _password_managers(p: Platform) -> Collected:
    found = present(
        "pass.store",
        [password_store_dir(p)],
        title="pass password store (usable while gpg-agent holds the key)",
        severity=Severity.MEDIUM,
        directories=True,
    )
    found.extend(
        present(
            "onepassword.cli",
            [p.xdg_config_home / "op", p.home / ".op"],
            title="1Password CLI set up (usable while the app is unlocked)",
            severity=Severity.MEDIUM,
            directories=True,
        )
    )
    return found


def _cookie_db(profile: Path) -> Path | None:
    for candidate in (profile / "Network" / "Cookies", profile / "Cookies"):
        if stat_entry(candidate).kind is Kind.FILE:
            return candidate
    return None


def _browsers(p: Platform) -> Collected:
    found = Collected()
    for browser, user_data in chromium_user_data_dirs(p):
        for name in list_directory(user_data) or []:
            profile = user_data / name
            if stat_entry(profile).kind is not Kind.DIRECTORY:
                continue
            cookies = _cookie_db(profile)
            if cookies is None:
                continue
            found.items.append(
                SensitiveItem(
                    id="browser.cookies",
                    title=f"{browser} session cookies (encrypted with a key you can read)",
                    path=str(cookies),
                    severity=Severity.MEDIUM,
                    facts=(Evidence("browser", "browser", browser),),
                )
            )
    profiles = firefox_profiles_dir(p)
    for name in list_directory(profiles) or []:
        cookies = profiles / name / "cookies.sqlite"
        if stat_entry(cookies).kind is Kind.FILE:
            found.items.append(
                SensitiveItem(
                    id="browser.cookies",
                    title="Firefox session cookies (not encrypted)",
                    path=str(cookies),
                    severity=Severity.HIGH,
                    facts=(Evidence("browser", "browser", "Firefox"),),
                )
            )
    return found
