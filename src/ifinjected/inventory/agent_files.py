"""The coding agents' own credentials and transcripts, and ``.env`` files near the work.

An agent's login token (``~/.claude/.credentials.json``, ``~/.codex/auth.json``…) is as
valuable as any API key: an injected agent can send it away and keep using the account.
Transcripts and history are plain text and keep whatever a tool printed, including a
secret read earlier in another session.

``.env`` files are listed in the workspace, in its direct subdirectories (monorepos) and
in every directory above it up to the home directory. They are only ``stat``ed; with
``--include-env`` their variable *names* are listed, never their values.
"""

from __future__ import annotations

from pathlib import Path

from ifinjected.files import Kind, RefusedError, list_directory, read_text, stat_entry
from ifinjected.homes import Platform, Scope, agent_locations
from ifinjected.inventory.base import Collected, Context
from ifinjected.inventory.presence import present
from ifinjected.models import AgentId, Evidence, SensitiveItem, Severity, SkippedFile
from ifinjected.parsers.dotenv import dotenv_names, is_env_file

MAX_PARENTS = 8
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target"}
)


def agent_role_paths(p: Platform, role: str) -> list[tuple[AgentId, Path]]:
    """Every agent's user-scope location with ``role`` (``auth``, ``transcripts``…)."""
    return [
        (loc.agent, loc.path)
        for agent in AgentId
        for loc in agent_locations(agent, p)
        if loc.role == role and loc.scope is Scope.USER
    ]


def env_directories(p: Platform, workspace: Path) -> list[Path]:
    """The workspace, its direct subdirectories, and the directories above it up to the
    home directory (at most :data:`MAX_PARENTS`)."""
    directories = [workspace]
    for name in list_directory(workspace) or []:
        child = workspace / name
        if name not in _SKIP_DIRS and stat_entry(child).kind is Kind.DIRECTORY:
            directories.append(child)
    for parent in list(workspace.parents)[:MAX_PARENTS]:
        directories.append(parent)
        if parent == p.home:
            break
    return directories


def collect_agent_files(context: Context) -> Collected:
    p = context.platform
    found = Collected()
    for agent, path in agent_role_paths(p, "auth"):
        found.extend(
            present(
                "agent.auth",
                [path],
                title=f"{agent.display_name} login token",
                severity=Severity.HIGH,
                facts=(Evidence("agent", "agent", agent.value),),
            )
        )
    for role, directories in (("transcripts", True), ("history", False)):
        what = "transcripts" if directories else "prompt history"
        for agent, path in agent_role_paths(p, role):
            found.extend(
                present(
                    "agent.transcripts",
                    [path],
                    title=f"{agent.display_name} {what} (may hold secrets from earlier sessions)",
                    severity=Severity.MEDIUM,
                    facts=(Evidence("agent", "agent", agent.value),),
                    directories=directories,
                )
            )
    if context.workspace is not None:
        found.extend(_env_files(context, context.workspace))
    return found


def _env_files(context: Context, workspace: Path) -> Collected:
    found = Collected()
    for directory in env_directories(context.platform, workspace):
        for name in list_directory(directory) or []:
            if not is_env_file(name):
                continue
            path = directory / name
            info = stat_entry(path)
            if info.kind is not Kind.FILE:
                continue
            facts: tuple[Evidence, ...] = ()
            if context.policy.include_env:
                names = _names(path, context, found)
                if names is not None:
                    facts = (Evidence("env", "variables", ", ".join(names)),)
            found.items.append(
                SensitiveItem(
                    id="env.file",
                    title=".env file in the workspace"
                    if directory == workspace or directory.parent == workspace
                    else ".env file above the workspace",
                    path=str(path),
                    severity=Severity.MEDIUM,
                    facts=facts,
                    readable_by_others=info.group_or_world_readable,
                )
            )
    return found


def _names(path: Path, context: Context, found: Collected) -> tuple[str, ...] | None:
    try:
        text = read_text(path, context.policy.max_file_bytes)
    except RefusedError as error:
        found.skipped.append(SkippedFile(str(path), str(error)))
        return None
    names = dotenv_names(text or "")
    del text
    return names
