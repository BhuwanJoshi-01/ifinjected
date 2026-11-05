"""docs/what-is-read.md, generated from the catalog so the two can never disagree."""

from __future__ import annotations

from ifinjected.inventory.catalog import load_catalog

_LEVELS = {
    "stat": "existence, permissions and size only (never opened)",
    "head": "the first {n} bytes",
    "full": "the whole file, parsed for structure; values dropped",
}
_BASES = {
    "home": "~",
    "xdg_config": "$XDG_CONFIG_HOME (~/.config)",
    "xdg_data": "$XDG_DATA_HOME (~/.local/share)",
    "appdata": "%APPDATA%",
    "gcloud": "gcloud's config directory",
    "azure": "Azure CLI's config directory",
    "gh": "GitHub CLI's config directory",
    "cargo": "$CARGO_HOME",
    "docker": "$DOCKER_CONFIG (~/.docker)",
    "kubeconfig": "each file in $KUBECONFIG",
    "huggingface": "Hugging Face's token file",
    "chromium": "each Chrome and Chromium user data directory",
    "firefox": "Firefox's profiles directory",
    "env_dirs": "the workspace, its subdirectories and the directories above it up to ~",
    "root": "the file system root",
    "docker_host": "the socket in $DOCKER_HOST",
    "agent_config": "every agent's configuration file",
    "agent_config_dir": "every agent's configuration directory",
    "workspace": "the workspace",
    "workspace_parents": "the workspace and its parents",
}


def _where(base: str, glob: str) -> str:
    if base.startswith("env:"):
        where = f"the path in ${base.removeprefix('env:')}"
    elif base.startswith("agent_role:"):
        where = f"every agent's {base.removeprefix('agent_role:')} file"
    else:
        where = _BASES.get(base, base)
    return where if glob in {".", ""} else f"{where} / `{glob}`"


def render_what_is_read() -> str:
    catalog = load_catalog()
    out = [
        "# What ifinjected reads",
        "",
        "Every path a scan may look at is declared here, with how deep it looks. A contract test",
        "records every look during whole scans and fails on any path that is not declared, or on",
        "a deeper look than declared. This file is generated from the catalog",
        "(`uv run python -m ifinjected.inventory.docs`); a test fails when the two differ.",
        "",
        f"Sources retrieved {catalog.retrieved}.",
        "",
        "| Item | Where | How deep | With `--deep` / `--include-env` |",
        "|---|---|---|---|",
    ]
    for entry in catalog.entries:
        where = (
            "<br>".join(_where(p.base, p.glob) for p in entry.paths)
            or "the environment (names only)"
        )
        level = _LEVELS[entry.level.value].format(n=entry.head_bytes)
        deeper = _LEVELS[entry.deep_level.value] if entry.deep_level else ""
        if entry.deep_level:
            deeper += " (`--include-env`)" if entry.deep_flag == "include_env" else " (`--deep`)"
        out.append(f"| **{entry.title}** (`{entry.id}`) | {where} | {level} | {deeper} |")
    out += ["", "## Why each item matters", ""]
    for entry in catalog.entries:
        sources = ", ".join(f"[{s.title}]({s.url})" for s in entry.sources)
        out.append(f"- **{entry.title}**: {entry.why} Sources: {sources}.")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    from pathlib import Path

    Path("docs/what-is-read.md").write_text(render_what_is_read(), encoding="utf-8")
