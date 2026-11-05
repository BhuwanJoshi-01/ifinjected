"""The catalog of sensitive items: what ifinjected looks for, where, and how deep.

``catalog.json`` is data with a date and a source for every entry. It is the contract
between the collectors and the privacy promise: a contract test runs whole scans with
the read ledger on and fails when a path was looked at that no entry declares, or at a
deeper level than its entry allows. ``docs/what-is-read.md`` is generated from it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import cache
from importlib.resources import files
from pathlib import Path, PurePath
from typing import Any

from ifinjected.files import Level
from ifinjected.homes import Platform

_BASES = (
    "home", "xdg_config", "xdg_data", "appdata", "gcloud", "azure", "gh", "cargo", "docker",
    "kubeconfig", "huggingface", "chromium", "firefox", "env_dirs", "root", "docker_host",
    "agent_config", "agent_config_dir", "workspace", "workspace_parents",
)  # fmt: skip
"""Also ``env:NAME``: the path in environment variable NAME (glob ``.`` for the path itself),
and ``agent_role:ROLE``: every agent's user-scope location with that role."""

FLAGS = ("deep", "include_env")
"""The opt-in flags that can deepen a look: ``--deep`` and ``--include-env``."""


class CatalogError(ValueError):
    """catalog.json is malformed; a bug in the package, caught by the tests."""


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    title: str
    url: str


@dataclass(frozen=True, slots=True)
class PathPattern:
    """``glob`` relative to a base directory (``home``, ``xdg_config``…, ``workspace``
    or ``workspace_parents``: the workspace and every directory above it)."""

    base: str
    glob: str


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    title: str
    why: str
    level: Level
    paths: tuple[PathPattern, ...]
    sources: tuple[Source, ...]
    head_bytes: int | None = None
    deep_level: Level | None = None
    """The level with the opt-in flag; ``None`` when no flag reads anything more."""
    deep_flag: str = "deep"
    """The flag that unlocks :attr:`deep_level`: ``deep`` or ``include_env``."""

    def level_for(self, flags: frozenset[str]) -> Level:
        if self.deep_level is not None and self.deep_flag in flags:
            return self.deep_level
        return self.level


@dataclass(frozen=True, slots=True)
class Catalog:
    retrieved: str
    entries: tuple[Entry, ...]

    def entry(self, item_id: str) -> Entry:
        for entry in self.entries:
            if entry.id == item_id:
                return entry
        raise KeyError(item_id)

    def declared_level(
        self,
        path: Path,
        platform: Platform,
        workspace: Path | None,
        *,
        deep: bool = False,
        include_env: bool = False,
    ) -> Level | None:
        """The deepest level any entry allows for ``path``, or ``None`` if none declares it."""
        order = list(Level)
        flags = frozenset(f for f, on in (("deep", deep), ("include_env", include_env)) if on)
        found: Level | None = None
        for entry in self.entries:
            level = entry.level_for(flags)
            for pattern in entry.paths:
                for base in _base_dirs(pattern.base, platform, workspace):
                    if _matches(path, base, pattern.glob) and (
                        found is None or order.index(level) > order.index(found)
                    ):
                        found = level
        return found


def _base_dirs(base: str, platform: Platform, workspace: Path | None) -> list[Path]:
    # Imported here: the collectors import the catalog, and these resolvers live with them.
    from ifinjected.inventory.agent_files import agent_role_paths, env_directories
    from ifinjected.inventory.cloud import azure_dir, gcloud_dir
    from ifinjected.inventory.containers import docker_config_file, kubeconfig_files
    from ifinjected.inventory.environment import docker_sockets
    from ifinjected.inventory.tools import (
        chromium_user_data_dirs,
        firefox_profiles_dir,
        huggingface_token_file,
    )
    from ifinjected.inventory.vcs import cargo_home, gh_config_dir

    if base.startswith("env:"):
        value = platform._env_path(base.removeprefix("env:"))
        return [value] if value is not None else []
    if base.startswith("agent_role:"):
        return [path for _, path in agent_role_paths(platform, base.removeprefix("agent_role:"))]
    if base in {"agent_config", "agent_config_dir"}:
        from ifinjected.homes import agent_locations
        from ifinjected.models import AgentId

        directories = {"managed_settings_dir", "policies", "profiles", "config_dir"}
        data = {"auth", "transcripts", "history", "accounts"}
        found = []
        for agent in AgentId:
            for location in agent_locations(agent, platform, workspace):
                if location.role in data:
                    continue
                is_dir = location.role in directories
                if (base == "agent_config_dir") == is_dir:
                    found.append(location.path)
        return found
    if base == "env_dirs":
        if workspace is None:
            return []
        from ifinjected.files import _LEDGER

        token = _LEDGER.set(None)  # resolving the catalog is not part of the scan
        try:
            return env_directories(platform, workspace)
        finally:
            _LEDGER.reset(token)
    resolvers = {
        "gcloud": lambda: [gcloud_dir(platform)],
        "azure": lambda: [azure_dir(platform)],
        "gh": lambda: [gh_config_dir(platform)],
        "cargo": lambda: [cargo_home(platform)],
        "docker": lambda: [docker_config_file(platform).parent],
        "kubeconfig": lambda: kubeconfig_files(platform),
        "huggingface": lambda: [huggingface_token_file(platform)],
        "chromium": lambda: [d for _, d in chromium_user_data_dirs(platform)],
        "firefox": lambda: [firefox_profiles_dir(platform)],
        "root": lambda: [platform.root],
        "docker_host": lambda: docker_sockets(platform)[:1],
    }
    if base in resolvers:
        return resolvers[base]()
    if base == "home":
        return [platform.home]
    if base == "xdg_config":
        return [platform.xdg_config_home]
    if base == "xdg_data":
        return [platform.xdg_data_home]
    if base == "appdata":
        return [platform.appdata]
    if workspace is None:
        return []
    if base == "workspace":
        return [workspace]
    return [workspace, *workspace.parents]


def _matches(path: Path, base: Path, glob: str) -> bool:
    try:
        relative = PurePath(path).relative_to(base)
    except ValueError:
        return False
    if glob in {".", ""}:
        return relative == PurePath()
    return fnmatchcase(relative.as_posix(), glob)


@cache
def load_catalog() -> Catalog:
    """The catalog shipped with the package, checked on load."""
    raw = files("ifinjected.inventory").joinpath("catalog.json").read_text(encoding="utf-8")
    return parse_catalog(json.loads(raw))


def parse_catalog(data: dict[str, Any]) -> Catalog:
    sources = {
        key: Source(key, value["title"], value["url"]) for key, value in data["sources"].items()
    }
    for source in sources.values():
        if not source.url.startswith("https://"):
            raise CatalogError(f"source {source.id} needs an https URL")
    entries = []
    seen: set[str] = set()
    for item in data["items"]:
        if item["id"] in seen:
            raise CatalogError(f"duplicate catalog id {item['id']}")
        seen.add(item["id"])
        if not item.get("sources"):
            raise CatalogError(f"{item['id']} has no source")
        unknown = [s for s in item["sources"] if s not in sources]
        if unknown:
            raise CatalogError(f"{item['id']} cites unknown sources {unknown}")
        level = Level(item["level"])
        deep_level = Level(item["deep_level"]) if "deep_level" in item else None
        deep_flag = item.get("deep_flag", "deep")
        if deep_flag not in FLAGS:
            raise CatalogError(f"{item['id']}: unknown deep_flag {deep_flag}")
        head_bytes = item.get("head_bytes")
        if (level is Level.HEAD) != (head_bytes is not None):
            raise CatalogError(f"{item['id']}: head_bytes is required for head and only for head")
        patterns = tuple(PathPattern(p["base"], p["glob"]) for p in item["paths"])
        for pattern in patterns:
            if pattern.base not in _BASES and not pattern.base.startswith(("env:", "agent_role:")):
                raise CatalogError(f"{item['id']}: unknown base {pattern.base}")
        entries.append(
            Entry(
                id=item["id"],
                title=item["title"],
                why=item["why"],
                level=level,
                paths=patterns,
                sources=tuple(sources[s] for s in item["sources"]),
                head_bytes=head_bytes,
                deep_level=deep_level,
                deep_flag=deep_flag,
            )
        )
    return Catalog(retrieved=data["retrieved"], entries=tuple(entries))
