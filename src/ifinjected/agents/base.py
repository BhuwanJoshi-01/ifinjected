"""What every agent adapter produces, and the sourced facts adapters rely on.

An adapter reads one agent's configuration layers as data and returns an
:class:`AgentReport`: which layers it found (and which it could not read), the merged
:class:`~ifinjected.policy.model.EffectivePolicy`, the MCP servers and hooks it would
start, and notes on what could not be decided. Nothing an agent is configured to run is
ever run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from ifinjected.files import RefusedError, read_text
from ifinjected.homes import Scope
from ifinjected.models import AgentId, SourceRef
from ifinjected.parsers.positions import ConfigSyntaxError, Document, parse_json, parse_toml
from ifinjected.policy.model import EffectivePolicy


@dataclass(frozen=True, slots=True)
class Fact:
    id: str
    text: str
    source_title: str
    source_url: str


@cache
def load_facts() -> dict[str, Fact]:
    """The dated, sourced facts in ``agents/data.json``; every one needs an https source."""
    raw = files("ifinjected.agents").joinpath("data.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    facts = {}
    for fact_id, fact in data["facts"].items():
        source = data["sources"][fact["source"]]
        if not source["url"].startswith("https://"):
            raise ValueError(f"fact {fact_id} needs an https source")
        facts[fact_id] = Fact(fact_id, fact["text"], source["title"], source["url"])
    return facts


def fact(fact_id: str) -> Fact:
    return load_facts()[fact_id]


@dataclass(frozen=True, slots=True)
class ConfigLayer:
    """One configuration file an agent reads: whose it is, whether it exists, whether it
    applies (an untrusted project's file may not), and why it could not be read."""

    agent: AgentId
    scope: Scope
    path: str
    exists: bool
    trusted: bool | None = None
    skipped: str | None = None


@dataclass(frozen=True, slots=True)
class McpServer:
    """An MCP server an agent starts or connects to.

    Only what identifies the server is kept: its name, transport, the program (and, for
    ``npx``/``uvx``-style launchers, the package) or the URL's host, and the *names* of
    its environment variables and headers. Arguments and values are never kept: they
    often carry tokens.
    """

    agent: AgentId
    name: str
    scope: Scope
    transport: str
    program: str | None = None
    package: str | None = None
    host: str | None = None
    env_names: tuple[str, ...] = ()
    header_names: tuple[str, ...] = ()
    approved: bool | None = None
    source: SourceRef | None = None


@dataclass(frozen=True, slots=True)
class Hook:
    """A command an agent runs on an event; only the program name is kept."""

    agent: AgentId
    event: str
    program: str
    scope: Scope
    source: SourceRef | None = None


@dataclass(frozen=True, slots=True)
class AgentReport:
    """Everything one adapter found. ``found`` is False when the agent leaves no trace on
    this machine (no configuration, no credentials)."""

    agent: AgentId
    found: bool
    layers: tuple[ConfigLayer, ...] = ()
    policy: EffectivePolicy | None = None
    mode: str | None = None
    mcp_servers: tuple[McpServer, ...] = ()
    hooks: tuple[Hook, ...] = ()
    settings: tuple[tuple[str, str, SourceRef | None], ...] = ()
    """Notable settings as (name, value, where), for the ``agents`` view."""
    notes: tuple[str, ...] = ()
    facts: tuple[str, ...] = field(default_factory=tuple)
    """Ids of the facts in data.json the result relies on."""


@dataclass(frozen=True, slots=True)
class Loaded:
    """A configuration file read for an adapter: its document, or why there is none."""

    path: Path
    document: Document | None
    exists: bool
    problem: str | None = None


def load_config(path: Path, max_bytes: int, *, kind: str = "json") -> Loaded:
    """Read and parse ``path`` as ``json``, ``jsonc`` or ``toml``. Never raises: a missing
    file has ``exists=False``, an unusable one a ``problem``."""
    try:
        text = read_text(path, max_bytes)
    except RefusedError as error:
        return Loaded(path, None, True, str(error))
    if text is None:
        return Loaded(path, None, False)
    try:
        if kind == "toml":
            document = parse_toml(text)
        else:
            document = parse_json(text, comments=kind == "jsonc")
    except ConfigSyntaxError as error:
        return Loaded(path, None, True, str(error))
    return Loaded(path, document, True)


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


_LAUNCHERS = frozenset({"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"})
_PACKAGE_FLAGS = frozenset({"--from", "-p", "--package"})
"""Launcher flags whose value is the package (``uvx --from x``, ``npx -p x``)."""
_VALUE_FLAGS = frozenset(
    {"--python", "--with", "--index", "--index-url", "--extra-index-url", "--registry",
     "--cache", "--userconfig", "--spec", "--pip-args", "-c", "--call"}
)  # fmt: skip
"""Launcher flags that take a value that is not the package (``uvx --python 3.11 x``)."""


_DOCKER_VALUE_FLAGS = frozenset(
    {"-e", "--env", "--env-file", "-v", "--volume", "--name", "-p", "--publish", "--network",
     "-w", "--workdir", "--entrypoint", "-u", "--user", "--mount", "--platform", "-l", "--label"}
)  # fmt: skip


def _docker_image(args: list[str]) -> str | None:
    """The image of ``docker run [flags] IMAGE [command]``."""
    if "run" not in args:
        return None
    rest = args[args.index("run") + 1 :]
    skip = False
    for arg in rest:
        if skip:
            skip = False
            continue
        if arg in _DOCKER_VALUE_FLAGS:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        name = arg.rsplit("/", 1)[-1]
        return arg.rsplit(":", 1)[0] if ":" in name else arg  # drop the tag, keep host:port
    return None


def _launched_package(args: list[str]) -> str | None:
    skip = False
    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg in _PACKAGE_FLAGS and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(tuple(f"{f}=" for f in _PACKAGE_FLAGS)):
            return arg.split("=", 1)[1]
        if arg in _VALUE_FLAGS:
            skip = True
            continue
        if not arg.startswith("-"):
            return arg
    return None


def describe_command(command: Any, args: Any) -> tuple[str | None, str | None]:
    """(program, package) of an MCP server or hook command: ``npx -y @x/server --token
    abc`` gives ``("npx", "@x/server")``. Nothing else of the command line is kept."""
    if isinstance(command, list):
        parts = [str(c) for c in command]
    elif isinstance(command, str):
        parts = command.split()
    else:
        return None, None
    parts += [str(a) for a in args] if isinstance(args, list) else []
    if not parts:
        return None, None
    program = Path(parts[0]).name
    package = None
    rest = parts[1:]
    if program in {"pnpm", "yarn", "npm"} and rest[:1] in (["dlx"], ["exec"], ["x"]):
        rest = rest[1:]
        program = f"{program} {parts[1]}"
    if program.split()[0] in _LAUNCHERS or program in {"pnpm dlx", "yarn dlx", "npm exec"}:
        package = _launched_package(rest)
    elif program in {"docker", "podman"}:
        package = _docker_image(rest)
    return program, package
