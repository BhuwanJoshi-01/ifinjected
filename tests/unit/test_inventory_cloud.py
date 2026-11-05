"""AWS, Google Cloud and Azure credentials (IFJ-011)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ifinjected.files import Level, recording
from ifinjected.homes import System
from ifinjected.inventory.base import Context
from ifinjected.inventory.catalog import load_catalog
from ifinjected.inventory.cloud import azure_dir, collect_cloud, gcloud_dir
from ifinjected.models import Policy, Severity
from ifinjected.parsers.ini import ini_sections
from tests import canaries
from tests.homes import FakeMachine


def _collect(machine: FakeMachine, deep: bool = False) -> dict[str, tuple[str, Severity]]:
    context = Context(platform=machine.platform(), policy=Policy(deep=deep))
    found = collect_cloud(context)
    return {Path(i.path).name: (i.title, i.severity) for i in found.items}


def test_nothing_when_no_cloud_cli_was_ever_used(tmp_path: Path) -> None:
    assert _collect(FakeMachine(tmp_path)) == {}


def test_aws_files_are_only_stated_without_deep(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    with recording() as ledger:
        found = _collect(machine)
    assert found["credentials"] == ("AWS credentials file", Severity.HIGH)
    assert {a.level for a in ledger.accesses} == {Level.STAT}


def test_deep_tells_static_keys_from_sso_and_never_keeps_a_value(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(
        ".aws/config",
        "[default]\nregion = eu-west-1\n"
        "[profile work]\nsso_session = acme\nsso_account_id = 111122223333\n"
        "[sso-session acme]\nsso_start_url = https://acme.awsapps.com/start\n",
    )
    context = Context(platform=machine.platform(), policy=Policy(deep=True))
    found = collect_cloud(context)
    by_name = {Path(i.path).name: i for i in found.items}
    credentials = by_name["credentials"]
    assert credentials.title == "AWS static access keys"
    assert credentials.fact("static_keys") == "default"
    config = by_name["config"]
    assert config.fact("profiles") == "default, work, sso-session acme"
    assert config.fact("sso") == "work"
    assert config.severity is Severity.LOW
    assert canaries.MARK not in repr(found)
    assert "111122223333" not in repr(found)


def test_temporary_keys_and_credential_processes_are_medium(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    machine.write(
        ".aws/credentials",
        "[ci]\naws_access_key_id = ASIAXXXX\naws_secret_access_key = x\naws_session_token = y\n",
    )
    machine.write(".aws/config", "[profile vault]\ncredential_process = aws-vault exec x --json\n")
    found = _collect(machine, deep=True)
    assert found["credentials"] == ("AWS temporary credentials", Severity.MEDIUM)
    assert found["config"] == ("AWS credential process", Severity.MEDIUM)


def test_aws_overrides_move_the_files(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path, env={"AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "c.ini")})
    (tmp_path / "c.ini").write_text("[x]\naws_access_key_id = a\n", encoding="utf-8")
    assert _collect(machine)["c.ini"] == ("AWS credentials file", Severity.HIGH)


def test_aws_session_caches_are_directories(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    (machine.home / ".aws" / "sso" / "cache").mkdir(parents=True)
    found = collect_cloud(Context(platform=machine.platform(), policy=Policy()))
    assert [(i.id, i.readable_by_others) for i in found.items] == [("aws.sso_cache", None)]


def test_gcloud_credentials_and_adc_type(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    gcloud = gcloud_dir(machine.platform())
    machine.write_at(gcloud / "credentials.db", b"SQLite format 3\x00")
    machine.write_at(
        gcloud / "application_default_credentials.json",
        {"type": "authorized_user", "refresh_token": canaries.GOOGLE_REFRESH, "client_id": "x"},
    )
    found = collect_cloud(Context(platform=machine.platform(), policy=Policy(deep=True)))
    adc = next(i for i in found.items if i.id == "gcloud.adc")
    assert adc.fact("type") == "authorized_user"
    assert {i.id for i in found.items} == {"gcloud.credentials", "gcloud.adc"}
    assert canaries.MARK not in repr(found)


def test_unparseable_adc_is_still_reported_and_noted(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    adc = gcloud_dir(machine.platform()) / "application_default_credentials.json"
    machine.write_at(adc, "{not json")
    found = collect_cloud(Context(platform=machine.platform(), policy=Policy(deep=True)))
    assert [i.id for i in found.items] == ["gcloud.adc"]
    assert [s.reason for s in found.skipped] == ["is not valid JSON"]


def test_gcloud_lives_in_appdata_on_windows(tmp_path: Path) -> None:
    p = FakeMachine(tmp_path, System.WINDOWS).platform()
    assert gcloud_dir(p) == p.appdata / "gcloud"
    moved = FakeMachine(tmp_path, env={"CLOUDSDK_CONFIG": "/g"}).platform()
    assert gcloud_dir(moved) == Path("/g")


def test_azure_token_cache_and_service_principals(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    directory = azure_dir(machine.platform())
    machine.write_at(directory / "msal_token_cache.json", "{}")
    machine.write_at(directory / "service_principal_entries.json", "[]")
    found = _collect(machine)
    assert found["msal_token_cache.json"] == ("Azure CLI token cache", Severity.HIGH)
    assert found["service_principal_entries.json"][0] == "Azure CLI service principal secrets"


@pytest.mark.parametrize("deep", [False, True])
def test_every_look_is_declared_in_the_catalog_at_its_level(tmp_path: Path, deep: bool) -> None:
    machine = FakeMachine(tmp_path)
    machine.add_credentials()
    machine.write(".aws/config", "[default]\n")
    gcloud = gcloud_dir(machine.platform())
    machine.write_at(gcloud / "application_default_credentials.json", {"type": "service_account"})
    platform = machine.platform()
    catalog = load_catalog()
    with recording() as ledger:
        collect_cloud(Context(platform=platform, policy=Policy(deep=deep)))
    order = list(Level)
    for access in ledger.accesses:
        declared = catalog.declared_level(Path(access.path), platform, None, deep=deep)
        assert declared is not None, access.path
        assert order.index(access.level) <= order.index(declared), access


def test_ini_sections_keep_key_names_only() -> None:
    sections = ini_sections(
        "; comment\nstray = value\n[default]\nAWS_Access_Key_ID = AKIA\n  continued\n"
        "[ empty ]\n# x\n"
    )
    assert [(s.name, sorted(s.keys)) for s in sections] == [
        ("default", ["aws_access_key_id"]),
        ("empty", []),
    ]
    assert "AKIA" not in repr(sections)
