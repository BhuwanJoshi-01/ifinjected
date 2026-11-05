# Contributing

Thanks for helping! By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). The most useful
contributions right now:

- **Agent configurations we read wrong.** A setup where `ifinjected` says an agent can reach something it can't,
  or misses something it can. Open a *Test report* issue with the redacted report and the agent's version.
- **New agents and new credential locations.** Each one is a small, well-defined pull request: a catalog entry
  with its source, a fixture and a test. Look for the `good first issue` label.
- **Fixtures** of real configuration files. Never include real credentials; use obviously fake ones like
  `sk-ant-FAKE-NOT-A-REAL-KEY`.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Git. No coding agent needs to be installed to run the tests: every
agent configuration is built in a temporary fake home directory.

```bash
git clone https://github.com/BhuwanJoshi-01/ifinjected.git
cd ifinjected
uv sync
```

Before every commit, run the same checks as CI:

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q
```

## How the code is organised

1. **CLI** parses arguments and wires the other layers together. No inference lives here.
2. **Agent adapters** read each agent's configuration layers (managed, user, project, local) as data, with the file
   and line every setting came from, and merge them the way that agent does into an *effective policy*.
3. **The inventory** finds sensitive items that exist on this machine (SSH keys, cloud credentials, tokens,
   `.env` files, secret-looking environment variable names) without reading their values.
4. **The policy engine** decides, for each agent and each item, how it could be reached: without approval,
   around a deny rule, after an approval, or not at all, and whether that is claimed by configuration or proven by
   the probe.
5. **The trifecta analysis** combines private data, untrusted input and ways out into a verdict and a grade.
6. **Rules** are pure functions from those facts to findings with stable codes (`IFJ-READ-003`).
7. **Renderers** produce terminal, JSON, Markdown, SARIF and the share card, after redaction.

## Rules for changes

- **Secrets never leave the parser.** A credential file is identified by its location and shape; its value is
  never kept in a model, a log or a report. Environment variables are names only.
- **Never execute what an agent is configured to run** (MCP servers, hooks, helpers, plugins).
- **Read only declared paths, write nothing, use no network** during a scan.
- **Every agent fact has a source.** Configuration semantics come from the agent's documentation or source code,
  with a URL and a date. What is not documented is reported as `unknown`.
- **Subprocesses** take an argument list (never `shell=True`), a timeout and an output limit, and go through the
  command runner so tests can replace them.
- **Tests first** where you can: add tests marked `@pytest.mark.xfail(strict=True, reason="IFJ-0xx")`, then
  implement the behaviour and remove the marker.

## Commits and pull requests

- One logical change per commit, with an imperative subject (at most 72 characters) and a body that explains why.
- Mention the requirement ID when there is one, as a `Refs: IFJ-005` trailer.
- Fill in the pull request template: it asks about execution, privacy and false alarms for a reason.
