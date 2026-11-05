"""What an MCP server can do, from a dated, sourced catalog of well-known servers.

Each server is matched by its package (``@modelcontextprotocol/server-github``), a package
prefix (``awslabs.``) or the host of its URL (``api.githubcopilot.com``). Its capabilities
feed the trifecta:

* ``untrusted_input``: brings in content others can write (issues, web pages, messages);
* ``exfiltration``: can send data out (comments, posts, arbitrary URLs, API writes);
* ``private_data``: reads data that is not public (private repositories, databases);
* ``reads_files`` / ``writes_files``: touches the local disk, outside any agent sandbox;
* ``runs_code``: runs code it is given.

A server the catalog does not know is *unknown*, never harmless: a local one runs with
your full access, and anything it does is invisible to the agent's rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from importlib.resources import files

from ifinjected.agents.base import McpServer


class Capability(StrEnum):
    UNTRUSTED_INPUT = "untrusted_input"
    EXFILTRATION = "exfiltration"
    PRIVATE_DATA = "private_data"
    READS_FILES = "reads_files"
    WRITES_FILES = "writes_files"
    RUNS_CODE = "runs_code"


@dataclass(frozen=True, slots=True)
class CatalogServer:
    id: str
    title: str
    packages: tuple[str, ...]
    package_prefixes: tuple[str, ...]
    hosts: tuple[str, ...]
    capabilities: frozenset[Capability]
    source: str
    note: str


@dataclass(frozen=True, slots=True)
class Classification:
    """What is known about one configured server. ``known`` is False when the catalog has
    no entry; ``local`` when it runs on this machine (stdio) rather than remotely."""

    server: McpServer
    known: bool
    local: bool
    capabilities: frozenset[Capability]
    entry: CatalogServer | None = None

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities


@cache
def load_mcp_catalog() -> tuple[CatalogServer, ...]:
    raw = files("ifinjected.trifecta").joinpath("mcp_catalog.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    servers = []
    for item in data["servers"]:
        if not item["source"].startswith("https://"):
            raise ValueError(f"MCP catalog entry {item['id']} needs an https source")
        match = item["match"]
        servers.append(
            CatalogServer(
                id=item["id"],
                title=item["title"],
                packages=tuple(match.get("packages", ())),
                package_prefixes=tuple(match.get("package_prefixes", ())),
                hosts=tuple(match.get("hosts", ())),
                capabilities=frozenset(Capability(c) for c in item["capabilities"]),
                source=item["source"],
                note=item["note"],
            )
        )
    return tuple(servers)


def _bare_package(package: str) -> str:
    """``@x/server@1.2.3`` and ``x-mcp==1.0`` without their versions."""
    if package.startswith("@"):
        scope, _, rest = package.partition("/")
        return f"{scope}/{rest.split('@', 1)[0]}"
    for separator in ("==", "@", ">=", "~="):
        package = package.split(separator, 1)[0]
    return package


def _host_matches(host: str, wanted: str) -> bool:
    return host == wanted or host.endswith("." + wanted)


def classify(server: McpServer) -> Classification:
    local = server.transport == "stdio" or server.program is not None
    package = _bare_package(server.package) if server.package else None
    for entry in load_mcp_catalog():
        if package is not None and (
            package in entry.packages or any(package.startswith(p) for p in entry.package_prefixes)
        ):
            return Classification(server, True, local, entry.capabilities, entry)
        if server.host is not None and any(_host_matches(server.host, h) for h in entry.hosts):
            return Classification(server, True, local, entry.capabilities, entry)
    return Classification(server, False, local, frozenset())
