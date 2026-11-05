# AGENTS.md

Guide for contributors and coding agents. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the rules in full.

## What this is

A read-only Python CLI that answers one question: **if a coding agent on this machine got prompt-injected right
now, what could it reach?** It reads the configuration of Claude Code, Codex, Gemini CLI, Cursor, opencode and
Copilot CLI as data, takes stock of the credentials that exist on the machine without reading their values,
works out for each agent which of them it could read (with or without an approval, around which rules) and
where it could send them. Plain Python 3.11+, Typer and Rich, packaged with uv (`uv_build` backend), `src/`
layout. Command: `ifinjected`.

## Commands

```bash
uv sync                                    # create .venv with the dev tools
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q   # what CI runs
uv run pytest -q --cov                     # with coverage
```

## Layout

```
src/ifinjected/   the package (layers listed in CONTRIBUTING.md, filled in as they land)
tests/
  conftest.py     autouse no_network guard (UNIX sockets allowed); HYPOTHESIS_PROFILE=thorough
  unit/           unit tests
  contract/       privacy and output contracts
docs/roadmap.md   requirement IDs IFJ-001 … and what 0.1 includes
```

The core (runner, privacy, models, CLI shell) follows worktree-shield and gpu-stack-inspector; each project keeps
its own copy on purpose.

## Rules that are easy to break

- **Never print, store or log a secret value.** Credential files are `stat`ed; key files are read up to their
  header only; deeper parsing (`--deep`) keeps structure (profile and host names) and drops every value inside
  the parser. Environment variables and `.env` files are reported by **name** only.
- **Never execute anything an agent is configured to run**: no MCP server commands, hooks, `apiKeyHelper`,
  `headersHelper`, status lines or plugins. Agent configuration is parsed as data, with size limits.
- **Read only what is declared.** Every path the scan may open is listed in a catalog (and in
  `docs/what-is-read.md`); a test records every open and fails on anything else.
- **Write nothing** except a file the user names with `--output`. No config is ever changed; `plan` only shows
  changes.
- **No network.** The only exception is `prove --run --network`, which makes one TCP connection the user asked
  for.
- **Prove mode is opt-in and opens, never reads.** The probe calls `open(O_RDONLY|O_NONBLOCK)` and `close()`, and
  nothing else, on the files it checks.
- **Be conservative.** A configuration fact that the docs do not state is `unknown`, not a guess. Every agent fact
  carries a dated source.
- Subprocesses: argument lists only (no `shell=True`), always a timeout and an output cap, always through the
  command runner.
- Test files with non-ASCII content are written with `encoding="utf-8"`: Windows CI defaults to cp1252.
- Tests first where possible: `@pytest.mark.xfail(strict=True, reason="IFJ-0xx")`, then implement and drop the
  marker.

## Commits

One logical change per commit; imperative subject of at most 72 characters; a body that explains why; a
`Refs: IFJ-0xx` trailer when a requirement applies. Every commit passes the CI command above.
