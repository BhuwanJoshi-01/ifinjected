"""Container and cluster credentials: Docker and Kubernetes.

Docker keeps registry passwords inline in ``config.json`` unless a credential store is
configured; with ``--deep`` the registries with inline credentials are named. A
kubeconfig holds tokens, client keys or passwords for clusters, or runs an exec plugin
to fetch them; with ``--deep`` the kinds are named, never the values.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected.homes import Platform
from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.presence import Refinement, each
from ifinjected.models import Evidence, Severity
from ifinjected.parsers.structure import docker_auth, yaml_keys


def docker_config_file(p: Platform) -> Path:
    directory = p._env_path("DOCKER_CONFIG") or p.home / ".docker"
    return directory / "config.json"


def kubeconfig_files(p: Platform) -> list[Path]:
    value = (p.env_value("KUBECONFIG") or "").strip()
    if value:
        separator = ";" if p.system.value == "windows" else ":"
        return [Path(part) for part in value.split(separator) if part.strip()]
    return [p.home / ".kube" / "config"]


def _docker(text: str) -> Refinement | None:
    auth = docker_auth(text)
    if auth is None:
        return None
    facts = []
    if auth.store:
        facts.append(Evidence("docker", "credential_store", auth.store))
    if auth.helpers:
        facts.append(Evidence("docker", "credential_helpers", ", ".join(auth.helpers)))
    if auth.inline:
        facts.append(Evidence("docker", "inline_registries", ", ".join(auth.inline)))
        return "Docker registry passwords (plain text)", Severity.HIGH, tuple(facts)
    if auth.store or auth.helpers:
        return "Docker registry logins (credential store)", Severity.MEDIUM, tuple(facts)
    return "Docker config (no registry logins)", Severity.LOW, tuple(facts)


_KUBE_SECRETS = {"token": "tokens", "client-key-data": "client keys", "client-key": "client keys",
                 "password": "passwords"}  # fmt: skip
_KUBE_PLUGINS = {"exec": "exec plugins", "auth-provider": "auth providers"}


def _kube(text: str) -> Refinement:
    names = {k.name for k in yaml_keys(text)}
    secrets = sorted({label for key, label in _KUBE_SECRETS.items() if key in names})
    plugins = sorted({label for key, label in _KUBE_PLUGINS.items() if key in names})
    facts = []
    if secrets:
        facts.append(Evidence("kube", "credentials", ", ".join(secrets)))
    if plugins:
        facts.append(Evidence("kube", "plugins", ", ".join(plugins)))
    if secrets:
        return "Kubernetes credentials (in the file)", Severity.HIGH, tuple(facts)
    if plugins:
        return "Kubernetes credentials (from a plugin)", Severity.MEDIUM, tuple(facts)
    return "Kubernetes config (no credentials)", Severity.LOW, tuple(facts)


def collect_containers(context: Context) -> Collected:
    p = context.platform
    found = each(
        context,
        "docker.config",
        [docker_config_file(p)],
        title="Docker config (may hold registry passwords)",
        severity=Severity.MEDIUM,
        analyse=_docker,
    )
    found.extend(
        each(
            context,
            "kube.config",
            kubeconfig_files(p),
            title="Kubernetes config",
            severity=Severity.HIGH,
            analyse=_kube,
        )
    )
    return found
