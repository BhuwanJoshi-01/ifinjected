## What does this change?

<!-- What and why, from the user's point of view. Link the issue if there is one. -->

Requirement IDs: <!-- e.g. IFJ-012, or "none" -->

## How was it tested?

<!-- Unit tests and fixtures added; real agent setups tried, if any (agent, version, system). -->

## Impact

- Reading: <!-- Does this open a new path? Is it in the catalog and docs/what-is-read.md, at which level? -->
- Privacy: <!-- Can any new field carry a secret value, an env value, or a path or name that identifies the user? -->
- Execution and writes: <!-- Can this start anything an agent is configured to run, or write anywhere? -->
- False alarms: <!-- Could this report reach that isn't real? Is every agent fact sourced? -->
- Compatibility: <!-- Changes to CLI flags, exit codes, finding IDs, the JSON schema or SARIF? -->

## Checklist

- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q` passes
- [ ] No secret value is kept past the parser; nothing an agent is configured to run is executed
- [ ] Negative cases are tested (malformed config, missing files, permission denied, secrets in input)
- [ ] CHANGELOG.md and docs updated if behaviour, flags or output changed
