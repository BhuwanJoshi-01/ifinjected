"""Cloud credentials: AWS, Google Cloud and Azure.

By default each file is only ``stat``ed: it exists, so a credential is there. With
``--deep`` the AWS files are parsed for their structure (profile names, and whether a
profile has static keys, temporary keys, single sign-on or a credential process) and the
Google application default credentials for their ``type``; every value is dropped as it
is read.
"""

from __future__ import annotations

import json
from pathlib import Path

from ifinjected.files import RefusedError, read_text
from ifinjected.homes import Platform, System
from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.presence import present
from ifinjected.models import Evidence, SensitiveItem, Severity, SkippedFile
from ifinjected.parsers.ini import Section, ini_sections


def aws_credentials_file(p: Platform) -> Path:
    return p._env_path("AWS_SHARED_CREDENTIALS_FILE") or p.home / ".aws" / "credentials"


def aws_config_file(p: Platform) -> Path:
    return p._env_path("AWS_CONFIG_FILE") or p.home / ".aws" / "config"


def gcloud_dir(p: Platform) -> Path:
    override = p._env_path("CLOUDSDK_CONFIG")
    if override is not None:
        return override
    if p.system is System.WINDOWS:
        return p.appdata / "gcloud"
    return (
        p.xdg_config_home / "gcloud"
        if p.env_value("XDG_CONFIG_HOME")
        else p.home / ".config" / "gcloud"
    )


def azure_dir(p: Platform) -> Path:
    return p._env_path("AZURE_CONFIG_DIR") or p.home / ".azure"


def collect_cloud(context: Context) -> Collected:
    found = Collected()
    found.extend(_aws(context))
    found.extend(_gcloud(context))
    found.extend(_azure(context))
    return found


# --- AWS ----------------------------------------------------------------------------------


def _profile_name(section: Section, config: bool) -> str:
    name = section.name
    if config and name.startswith("profile "):
        return name.removeprefix("profile ").strip()
    return name


def _aws_kinds(sections: tuple[Section, ...], config: bool) -> dict[str, list[str]]:
    kinds: dict[str, list[str]] = {"static": [], "temporary": [], "sso": [], "process": []}
    for section in sections:
        if config and section.name.startswith("sso-session"):
            continue
        name = _profile_name(section, config)
        keys = section.keys
        if "aws_access_key_id" in keys and "aws_session_token" in keys:
            kinds["temporary"].append(name)
        elif "aws_access_key_id" in keys:
            kinds["static"].append(name)
        if keys & {"sso_start_url", "sso_session"}:
            kinds["sso"].append(name)
        if "credential_process" in keys:
            kinds["process"].append(name)
    return kinds


def _aws_file(context: Context, path: Path, config: bool, found: Collected) -> None:
    item_id = "aws.config" if config else "aws.credentials"
    base = present(
        item_id,
        [path],
        title="AWS config" if config else "AWS credentials file",
        severity=Severity.MEDIUM if config else Severity.HIGH,
    )
    if not base.items:
        return
    item = base.items[0]
    if not context.policy.deep:
        found.items.append(item)
        return
    try:
        text = read_text(path, context.policy.max_file_bytes)
    except RefusedError as error:
        found.skipped.append(SkippedFile(str(path), str(error)))
        found.items.append(item)
        return
    sections = ini_sections(text or "")
    del text
    kinds = _aws_kinds(sections, config)
    facts = [Evidence("aws", "profiles", ", ".join(_profile_name(s, config) for s in sections))]
    facts += [
        Evidence(
            "aws", f"{kind}_keys" if kind in {"static", "temporary"} else kind, ", ".join(names)
        )
        for kind, names in kinds.items()
        if names
    ]
    if kinds["static"]:
        severity, title = Severity.HIGH, "AWS static access keys"
    elif kinds["temporary"] or kinds["process"]:
        severity, title = (
            Severity.MEDIUM,
            "AWS temporary credentials" if kinds["temporary"] else "AWS credential process",
        )
    elif config:
        severity, title = Severity.LOW, "AWS config (no keys)"
    else:
        severity, title = Severity.LOW, "AWS credentials file (no keys)"
    found.items.append(
        SensitiveItem(
            id=item_id,
            title=title,
            path=item.path,
            severity=severity,
            facts=tuple(facts),
            readable_by_others=item.readable_by_others,
        )
    )


def _aws(context: Context) -> Collected:
    p = context.platform
    found = Collected()
    _aws_file(context, aws_credentials_file(p), config=False, found=found)
    _aws_file(context, aws_config_file(p), config=True, found=found)
    found.extend(
        present(
            "aws.sso_cache",
            [p.home / ".aws" / "sso" / "cache", p.home / ".aws" / "cli" / "cache"],
            title="AWS cached session tokens",
            severity=Severity.MEDIUM,
            directories=True,
        )
    )
    return found


# --- Google Cloud -------------------------------------------------------------------------

_ADC_TYPES = {
    "authorized_user": "a user's refresh token",
    "service_account": "a service account key",
    "external_account": "workload identity federation",
    "impersonated_service_account": "service account impersonation",
}


def _gcloud(context: Context) -> Collected:
    directory = gcloud_dir(context.platform)
    found = present(
        "gcloud.credentials",
        [directory / "credentials.db", directory / "access_tokens.db"],
        title="Google Cloud CLI credentials",
        severity=Severity.HIGH,
    )
    found.extend(
        present(
            "gcloud.credentials",
            [directory / "legacy_credentials"],
            title="Google Cloud CLI legacy credentials",
            severity=Severity.HIGH,
            directories=True,
        )
    )
    adc = directory / "application_default_credentials.json"
    base = present(
        "gcloud.adc", [adc], title="Google application default credentials", severity=Severity.HIGH
    )
    for item in base.items:
        facts: tuple[Evidence, ...] = ()
        if context.policy.deep:
            kind = _adc_type(adc, found)
            if kind is not None:
                facts = (Evidence("gcloud", "type", kind),)
        found.items.append(
            SensitiveItem(
                item.id, item.title, item.path, item.severity, facts, item.readable_by_others
            )
        )
    return found


def _adc_type(path: Path, found: Collected) -> str | None:
    try:
        text = read_text(path, 256 * 1024)
        data = json.loads(text or "null")
    except RefusedError as error:
        found.skipped.append(SkippedFile(str(path), str(error)))
        return None
    except ValueError:
        found.skipped.append(SkippedFile(str(path), "is not valid JSON"))
        return None
    kind = data.get("type") if isinstance(data, dict) else None
    del data, text
    return kind if kind in _ADC_TYPES else None


# --- Azure --------------------------------------------------------------------------------


def _azure(context: Context) -> Collected:
    directory = azure_dir(context.platform)
    found = present(
        "azure.tokens",
        [
            directory / "msal_token_cache.json",
            directory / "msal_token_cache.bin",
            directory / "accessTokens.json",
        ],
        title="Azure CLI token cache",
        severity=Severity.HIGH,
    )
    found.extend(
        present(
            "azure.tokens",
            [
                directory / "service_principal_entries.json",
                directory / "service_principal_entries.bin",
            ],
            title="Azure CLI service principal secrets",
            severity=Severity.HIGH,
        )
    )
    return found
