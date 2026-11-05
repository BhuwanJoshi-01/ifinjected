"""Environment variable names and credential sockets (IFJ-016)."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ifinjected.inventory.base import Context
from ifinjected.inventory.environment import collect_environment, secret_variable_names
from ifinjected.models import Policy, Severity
from tests import canaries
from tests.homes import FakeMachine

posix_sockets = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(socket, "AF_UNIX"), reason="UNIX sockets"
)


def test_known_service_credentials_and_other_secret_names() -> None:
    env = {
        "OPENAI_API_KEY": canaries.OPENAI_KEY,
        "GITHUB_TOKEN": canaries.GH_TOKEN,
        "DATABASE_URL": "postgres://u:p@h/db",
        "OP_SESSION_my": canaries.SESSION,
        "MY_SERVICE_SECRET": canaries.ENV_VALUE,
        "SSH_AUTH_SOCK": "/run/ssh",
        "GOOGLE_APPLICATION_CREDENTIALS_FILE": "/x",
        "PATH": "/usr/bin",
        "XDG_SESSION_TYPE": "wayland",
        "KEYBOARD": "us",
    }
    known, other = secret_variable_names(env)
    assert known == ["DATABASE_URL", "GITHUB_TOKEN", "OPENAI_API_KEY", "OP_SESSION_my"]
    assert other == ["MY_SERVICE_SECRET"]


def test_variables_are_reported_by_name_only(tmp_path: Path) -> None:
    machine = FakeMachine(
        tmp_path, env={"ANTHROPIC_API_KEY": canaries.ANTHROPIC_KEY, "APP_TOKEN": "x"}
    )
    found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    by_title = {i.title: i for i in found.items}
    known = by_title["Service credentials in the environment"]
    assert (known.severity, known.fact("variables")) == (Severity.HIGH, "ANTHROPIC_API_KEY")
    assert by_title["Secret-looking variables in the environment"].fact("variables") == "APP_TOKEN"
    assert canaries.MARK not in repr(found)


def test_a_clean_environment_reports_nothing(tmp_path: Path) -> None:
    found = collect_environment(Context(platform=FakeMachine(tmp_path).platform(), policy=Policy()))
    assert found.items == []


def test_the_service_account_key_named_by_google_application_credentials(tmp_path: Path) -> None:
    key = tmp_path / "sa.json"
    key.write_text("{}", encoding="utf-8")
    machine = FakeMachine(tmp_path, env={"GOOGLE_APPLICATION_CREDENTIALS": str(key)})
    found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    assert [(i.path, i.severity) for i in found.items] == [(str(key), Severity.HIGH)]


@pytest.fixture
def short_dir() -> Iterator[Path]:
    # UNIX socket paths are limited to about 100 bytes; pytest's tmp_path can be longer.
    directory = Path(tempfile.mkdtemp(prefix="ifj", dir="/tmp" if os.name != "nt" else None))
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _listen(path: Path) -> socket.socket:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    return server


@posix_sockets
def test_ssh_agent_and_gpg_agent_sockets(tmp_path: Path, short_dir: Path) -> None:
    ssh = _listen(short_dir / "ssh")
    (short_dir / "gnupg").mkdir()
    gpg = _listen(short_dir / "gnupg" / "S.gpg-agent")
    try:
        machine = FakeMachine(
            tmp_path,
            env={"SSH_AUTH_SOCK": str(short_dir / "ssh"), "XDG_RUNTIME_DIR": str(short_dir)},
        )
        found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    finally:
        ssh.close()
        gpg.close()
    assert sorted((i.id, i.severity) for i in found.items) == [
        ("socket.gpg_agent", Severity.LOW),
        ("socket.ssh_agent", Severity.MEDIUM),
    ]


@posix_sockets
def test_a_writable_docker_socket_is_root(tmp_path: Path, short_dir: Path) -> None:
    server = _listen(short_dir / "docker.sock")
    try:
        machine = FakeMachine(tmp_path, env={"DOCKER_HOST": f"unix://{short_dir / 'docker.sock'}"})
        found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    finally:
        server.close()
    assert [(i.id, i.severity) for i in found.items] == [("socket.docker", Severity.HIGH)]


@posix_sockets
def test_a_socket_the_user_cannot_write_to_is_not_reported(tmp_path: Path, short_dir: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can write to anything")
    server = _listen(short_dir / "docker.sock")
    (short_dir / "docker.sock").chmod(0o400)
    try:
        machine = FakeMachine(tmp_path, env={"DOCKER_HOST": f"unix://{short_dir / 'docker.sock'}"})
        found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    finally:
        server.close()
    assert found.items == []


def test_a_regular_file_named_like_a_socket_is_not_a_socket(tmp_path: Path) -> None:
    fake = tmp_path / "agent.sock"
    fake.write_text("", encoding="utf-8")
    machine = FakeMachine(tmp_path, env={"SSH_AUTH_SOCK": str(fake)})
    found = collect_environment(Context(platform=machine.platform(), policy=Policy()))
    assert found.items == []
