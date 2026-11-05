# Machine-readable output

`ifinjected scan --format json` (or `report --format json --output FILE`) prints one JSON document. Its layout is
versioned by `schema_version`; fields are only added within a version, and anything incompatible bumps it.
Everything in it is redacted, exactly like the terminal output.

```json
{
  "schema_version": 1,
  "tool": "ifinjected",
  "tool_version": "0.1.0",
  "created_at": "2026-11-05T12:00:00Z",
  "summary": {
    "grade": "C",
    "agents": [{"agent": "claude_code", "grade": "C", "verdict": "full_gated"}],
    "problems": 12,
    "failing": 2,
    "strict_failure": true,
    "sensitive_items": 9
  },
  "system": "linux",
  "workspace": "~/src/app",
  "policy": {"...": "the effective .ifinjected.toml"},
  "items": [{"id": "ssh.key", "title": "...", "path": "~/.ssh/id_ed25519", "severity": "high", "facts": []}],
  "skipped": [],
  "exposures": [{"agent": "claude_code", "item": "ssh.key", "reach": "no_approval", "channel": "shell_recognized", "gate": "none"}],
  "findings": [{"id": "IFJ-READ-001", "status": "fail", "severity": "high", "summary": "...", "sources": []}],
  "agents": [{"agent": "claude_code", "found": true, "layers": [], "settings": [], "channels": [], "sandbox": {}}],
  "trifectas": [{"agent": "claude_code", "grade": "C", "verdict": "full_gated", "private": {"members": []}}]
}
```

| Field | Meaning |
|---|---|
| `summary.grade` | The machine's grade, the worst agent's (`null` when no agent was found) |
| `summary.strict_failure` | `true` when `--strict` exits with 1 |
| `items[].id` | The catalog entry (`docs/what-is-read.md`) |
| `exposures[].reach` | `no_approval`, `bypassable_rule`, `after_approval`, `blocked_by_rule`, `blocked_by_sandbox`, `not_present`, `unknown` |
| `exposures[].gate` | What stands in front: `none`, `automated`, `human`, `denied` |
| `findings[].id` | A stable code from `docs/rules.md` |
| `findings[].status` | `pass`, `warn`, `fail`, `unknown` |

## SARIF

`--format sarif` writes SARIF 2.1.0 for code scanning. Every rule is listed under `tool.driver.rules` with a link to
its section in `docs/rules.md`. Each failing, warning or unknown finding that points at a file becomes a result
(`error`, `warning`, `note`); paths inside the workspace are relative, so a code scanning upload annotates the right
line of `.claude/settings.json` or `.mcp.json`. `partialFingerprints["ifinjected/v1"]` is stable across runs.
CI validates the output against the official schema at a pinned commit.
