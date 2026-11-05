"""Fake machines: a home directory, a file system root and a workspace in a tmp dir.

Every agent's configuration and every credential is created here, never in the real
home. :meth:`FakeMachine.platform` resolves paths for Linux, macOS or Windows over the
same directory, so the whole suite runs the three systems' layouts on any CI runner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ifinjected.homes import Platform, System
from tests import canaries


@dataclass
class FakeMachine:
    base: Path
    system: System = System.LINUX
    env: dict[str, str] = field(default_factory=dict)

    @property
    def home(self) -> Path:
        name = "Users" if self.system is not System.LINUX else "home"
        return self.base / "root" / name / canaries.USER

    @property
    def root(self) -> Path:
        return self.base / "root"

    @property
    def workspace(self) -> Path:
        return self.home / "src" / "app"

    def platform(self) -> Platform:
        env = dict(self.env)
        env.setdefault("HOME", str(self.home))
        if self.system is System.WINDOWS:
            env.setdefault("USERPROFILE", str(self.home))
            env.setdefault("APPDATA", str(self.home / "AppData" / "Roaming"))
            env.setdefault("ProgramData", str(self.root / "ProgramData"))
            env.setdefault("ProgramFiles", str(self.root / "Program Files"))
        return Platform(system=self.system, home=self.home, env=env, root=self.root)

    def _write(self, path: Path, content: str | bytes | dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, dict):
            content = json.dumps(content, indent=2)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        return path

    def write(self, relative: str, content: str | bytes | dict[str, Any]) -> Path:
        """Write a file under the home directory (``".claude/settings.json"``)."""
        return self._write(self.home / relative, content)

    def write_at(self, path: Path, content: str | bytes | dict[str, Any]) -> Path:
        """Write a file at a path a resolver returned."""
        return self._write(path, content)

    def write_workspace(self, relative: str, content: str | bytes | dict[str, Any]) -> Path:
        return self._write(self.workspace / relative, content)

    def add_credentials(self) -> None:
        """A machine with one of everything a developer typically has lying around."""
        self.write(
            ".ssh/id_ed25519",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{canaries.SSH_KEY_BODY}\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
        )
        self.write(
            ".ssh/id_ed25519.pub", f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA {canaries.USER}@x\n"
        )
        self.write(
            ".aws/credentials",
            "[default]\n"
            f"aws_access_key_id = {canaries.AWS_ACCESS_KEY_ID}\n"
            f"aws_secret_access_key = {canaries.AWS_SECRET}\n",
        )
        self.write(
            ".config/gh/hosts.yml",
            f"github.com:\n    oauth_token: {canaries.GH_TOKEN}\n    user: {canaries.USER}\n",
        )
        self.write(".npmrc", f"//registry.npmjs.org/:_authToken={canaries.NPM_TOKEN}\n")
        self.write(".pypirc", f"[pypi]\nusername = __token__\npassword = {canaries.PYPI_TOKEN}\n")
        self.write(
            ".netrc",
            f"machine api.example.com login {canaries.USER} password {canaries.NETRC_PASSWORD}\n",
        )
        self.write(".docker/config.json", {"auths": {"ghcr.io": {"auth": canaries.DOCKER_AUTH}}})
        self.write(
            ".kube/config",
            "apiVersion: v1\nkind: Config\nusers:\n- name: dev\n  user:\n"
            f"    token: {canaries.KUBE_TOKEN}\n",
        )
        self.write_workspace(
            ".env", f"OPENAI_API_KEY={canaries.OPENAI_KEY}\nAPP_SECRET={canaries.ENV_VALUE}\n"
        )
