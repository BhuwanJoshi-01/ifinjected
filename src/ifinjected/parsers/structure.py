"""Small structure-only parsers for credential files. Every value is dropped as it is read.

Each function returns names (hosts, registries, profile keys), never the secret next to
them. They are deliberately simple and conservative: anything they cannot follow is
skipped, not guessed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class YamlKey:
    """A mapping key in a YAML document: its indentation and name, never its value."""

    indent: int
    name: str


_YAML_KEY = re.compile(r"^(?P<indent>[ ]*)(?:-[ ]+)?(?P<name>[A-Za-z0-9_.\-/:\"']+?)[ ]*:(?:[ ]|$)")


def yaml_keys(text: str) -> tuple[YamlKey, ...]:
    """The mapping keys of a simple YAML file (``gh``'s ``hosts.yml``, a kubeconfig).

    Block scalars, flow collections and anchors are not interpreted; their keys are
    still found line by line, which is all the callers need.
    """
    keys = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _YAML_KEY.match(line)
        if match:
            name = match.group("name").strip("\"'")
            indent = len(match.group("indent")) + (2 if line.lstrip().startswith("- ") else 0)
            keys.append(YamlKey(indent, name))
    return tuple(keys)


def top_level_keys(keys: tuple[YamlKey, ...]) -> tuple[str, ...]:
    return tuple(k.name for k in keys if k.indent == 0)


def credential_store_hosts(text: str) -> tuple[str, ...]:
    """Hosts in a git credential store (``https://user:token@host`` per line)."""
    hosts: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            host = urlsplit(line).hostname
        except ValueError:
            continue
        if host:
            hosts.append(host)
    return tuple(dict.fromkeys(hosts))


def netrc_machines(text: str) -> tuple[str, ...]:
    """``machine`` names in a netrc file (and ``default`` when there is one)."""
    words = text.split()
    machines: list[str] = []
    for index, word in enumerate(words):
        if word == "machine" and index + 1 < len(words):
            machines.append(words[index + 1])
        elif word == "default":
            machines.append("default")
    return tuple(dict.fromkeys(machines))


_NPMRC_AUTH = re.compile(
    r"^\s*(?P<scope>//[^\s=]+?/)?:?(?P<key>_authToken|_auth|_password|username)\s*=", re.MULTILINE
)


def npmrc_registries_with_auth(text: str) -> tuple[str, ...]:
    """Registries an ``.npmrc`` holds a token or password for (``//registry.npmjs.org/``);
    ``default`` for an unscoped ``_auth``."""
    registries = [
        (m.group("scope") or "default")
        for m in _NPMRC_AUTH.finditer(text)
        if m.group("key") != "username"
    ]
    return tuple(dict.fromkeys(registries))


@dataclass(frozen=True, slots=True)
class DockerAuth:
    """Registries with credentials inline in ``config.json`` (base64 user:password) and
    the credential helpers used for the others."""

    inline: tuple[str, ...]
    store: str | None
    helpers: tuple[str, ...]


def docker_auth(text: str) -> DockerAuth | None:
    """What ``~/.docker/config.json`` says about credentials, or ``None`` if not JSON."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    auths = data.get("auths")
    inline = []
    if isinstance(auths, dict):
        for registry, entry in auths.items():
            if isinstance(entry, dict) and (
                entry.get("auth") or entry.get("identitytoken") or entry.get("password")
            ):
                inline.append(str(registry))
    store = data.get("credsStore")
    helpers = data.get("credHelpers")
    result = DockerAuth(
        inline=tuple(inline),
        store=store if isinstance(store, str) and store else None,
        helpers=tuple(sorted(set(helpers.values()))) if isinstance(helpers, dict) else (),
    )
    del data, auths
    return result
