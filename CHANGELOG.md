# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/). The JSON report format has its own
`schema_version`, and finding IDs (`IFJ-READ-001` …) are stable: CI pipelines
and agents depend on both.

## Unreleased

The first release candidate.

- `ifinjected` (or `ifinjected scan`): a grade per agent from its lethal trifecta,
  then the findings with their reason, line and fix. `--strict` exits 1 on a failing
  finding; `--format json|markdown|sarif` for scripts and code scanning.
- Six agents: Claude Code, Codex, Gemini CLI, Cursor, opencode and Copilot CLI, each
  read from its documented configuration layers, with every behaviour cited in
  `src/ifinjected/agents/data.json`.
- An inventory of the credentials on the machine, found by location and file header
  only: `ifinjected inventory`, `--deep` for structure, `--include-env` for `.env`
  variable names.
- `ifinjected agents`, `plan`, `explain`, `rules`, `policy`, `report`, `card`,
  `share` and `badge`.
- 47 rules with stable codes (docs/rules.md, generated), a workspace policy
  (`.ifinjected.toml`), and docs/what-is-read.md generated from the catalog.
- `ifinjected prove --run [--network]`: an open-only probe run directly and under
  `codex sandbox`, turning Codex's claimed reach into proven or contradicted
  (IFJ-PROVE-001 to 003).
- Privacy contracts: a read ledger checked against the catalog, and canary secrets
  that must reach no output.
