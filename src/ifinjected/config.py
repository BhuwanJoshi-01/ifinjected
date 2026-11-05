"""The workspace policy, ``.ifinjected.toml``: TOML read as data, never run.

Precedence is flags, then the file at the top of the workspace, then the defaults in
:class:`~ifinjected.models.Policy`; there is no user-wide policy, so a CI job and a
developer get the same answer for the same repository. Anything the parser does not
know is an error rather than a silent default, so a misspelt key cannot quietly turn a
``deny`` back into a ``warn``.
"""

from __future__ import annotations

import dataclasses
import re
import tomllib
from pathlib import Path
from typing import Any

from ifinjected.files import RefusedError, read_text_inside
from ifinjected.models import DEFAULT_LEVELS, AgentId, Family, Policy, PolicyLevel

POLICY_FILE = ".ifinjected.toml"
MAX_POLICY_BYTES = 64 * 1024
SCHEMA_VERSION = 1
MAX_FILE_BYTES_LIMIT = 16 * 1024 * 1024

_FAMILY_KEYS = {family.policy_key: family for family in Family}
_SECTIONS: dict[str, tuple[str, ...]] = {
    "scan": ("agents", "deep", "include_env", "max_file_bytes"),
    "policy": tuple(_FAMILY_KEYS),
    "accept": ("items", "mcp_servers", "hosts"),
}
_ITEM_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_SERVER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_HOST = re.compile(r"(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})*")


class PolicyError(Exception):
    """The policy file cannot be used; the message names the file and the problem."""


def parse_policy(text: str, source: str) -> Policy:
    """The policy in ``text``; ``source`` names the file in messages and in the result."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"{source} is not valid TOML: {error}") from None
    try:
        return _policy(data, source)
    except _Invalid as error:
        raise PolicyError(f"{source}: {error}") from None


def load_policy(workspace: Path) -> Policy:
    """The policy of a workspace, or the defaults when it has no policy file.

    The file must be a regular file inside the workspace (a link may point elsewhere in
    it) and at most :data:`MAX_POLICY_BYTES` long.
    """
    path = workspace / POLICY_FILE
    try:
        text = read_text_inside(workspace, POLICY_FILE, MAX_POLICY_BYTES)
    except RefusedError as error:
        raise PolicyError(f"{path} {error}") from None
    if text is None:
        return Policy()
    return parse_policy(text, str(path))


def apply_overrides(
    policy: Policy,
    *,
    agents: tuple[AgentId, ...] | None = None,
    deep: bool | None = None,
    include_env: bool | None = None,
) -> Policy:
    """The policy with the settings given on the command line; ``None`` keeps the file's."""
    changes: dict[str, Any] = {}
    if agents:
        changes["agents"] = tuple(dict.fromkeys(agents))
    if deep is not None:
        changes["deep"] = deep
    if include_env is not None:
        changes["include_env"] = include_env
    return dataclasses.replace(policy, **changes) if changes else policy


class _Invalid(Exception):
    pass


def _policy(data: dict[str, Any], source: str) -> Policy:
    for key, value in data.items():
        if key == "schema_version":
            continue
        if key not in _SECTIONS:
            unknown = f"section [{key}]" if isinstance(value, dict) else f"key {key}"
            raise _Invalid(f"unknown {unknown}")
        if not isinstance(value, dict):
            raise _Invalid(f"{key} must be a section, written [{key}]")
        for name in value:
            if name not in _SECTIONS[key]:
                raise _Invalid(f"unknown key {key}.{name}")
    _schema_version(data)
    scan = data.get("scan", {})
    levels = data.get("policy", {})
    accept = data.get("accept", {})
    settings: dict[str, Any] = {}
    if "agents" in scan:
        settings["agents"] = _agents(scan["agents"])
    for flag in ("deep", "include_env"):
        if flag in scan:
            settings[flag] = _flag(scan, flag)
    if "max_file_bytes" in scan:
        settings["max_file_bytes"] = _max_file_bytes(scan["max_file_bytes"])
    if levels:
        merged = dict(DEFAULT_LEVELS)
        merged.update({_FAMILY_KEYS[name]: _level(levels, name) for name in levels})
        settings["levels"] = tuple(merged.items())
    if "items" in accept:
        settings["accept_items"] = _names(accept["items"], "accept.items", _ITEM_ID, "ssh.key")
    if "mcp_servers" in accept:
        settings["accept_mcp_servers"] = _names(
            accept["mcp_servers"], "accept.mcp_servers", _SERVER_NAME, "github"
        )
    if "hosts" in accept:
        settings["accept_hosts"] = _names(accept["hosts"], "accept.hosts", _HOST, "github.com")
    return Policy(**settings, source=source)


def _schema_version(data: dict[str, Any]) -> None:
    if "schema_version" not in data:
        raise _Invalid(
            f"schema_version is missing; start the file with schema_version = {SCHEMA_VERSION}"
        )
    version = data["schema_version"]
    if not _is_int(version):
        raise _Invalid(f"schema_version must be the number {SCHEMA_VERSION}, not {_shown(version)}")
    if version != SCHEMA_VERSION:
        raise _Invalid(
            f"schema_version {version} is not supported; this version reads {SCHEMA_VERSION}"
        )


def _agents(value: Any) -> tuple[AgentId, ...]:
    known = ", ".join(agent.value for agent in AgentId)
    if not isinstance(value, list) or not value:
        raise _Invalid(
            f'scan.agents must be a list of agents, like ["claude_code"]; known: {known}'
        )
    for item in value:
        if not isinstance(item, str) or item not in {agent.value for agent in AgentId}:
            raise _Invalid(f"scan.agents: {_shown(item)} is not an agent; known: {known}")
    return tuple(dict.fromkeys(AgentId(item) for item in value))


def _flag(section: dict[str, Any], name: str) -> bool:
    value = section[name]
    if not isinstance(value, bool):
        raise _Invalid(f"scan.{name} must be true or false, not {_shown(value)}")
    return value


def _max_file_bytes(value: Any) -> int:
    if not _is_int(value) or not 1 <= value <= MAX_FILE_BYTES_LIMIT:
        raise _Invalid(
            f"scan.max_file_bytes must be a whole number from 1 to {MAX_FILE_BYTES_LIMIT}, "
            f"not {_shown(value)}"
        )
    result: int = value
    return result


def _level(section: dict[str, Any], name: str) -> PolicyLevel:
    value = section[name]
    allowed = ", ".join(level.value for level in PolicyLevel)
    if not isinstance(value, str) or value not in {level.value for level in PolicyLevel}:
        raise _Invalid(f"policy.{name} must be one of {allowed}, not {_shown(value)}")
    return PolicyLevel(value)


def _names(value: Any, key: str, pattern: re.Pattern[str], example: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(v, str) and pattern.fullmatch(v) for v in value
    ):
        raise _Invalid(f'{key} must be a list of names, like ["{example}"]')
    return tuple(dict.fromkeys(value))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shown(value: Any) -> str:
    """A value from the file for a message: repr() escapes control characters."""
    shown = repr(value)
    return shown if len(shown) <= 40 else shown[:39] + "…"
