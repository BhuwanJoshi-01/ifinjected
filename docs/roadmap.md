# Roadmap

Requirement IDs are referenced from commits (`Refs: IFJ-012`) and tests. IDs are never reused.

## 0.1: answer the question for six agents, read-only

### Foundations

| ID | Requirement |
|---|---|
| IFJ-001 | `ifinjected --version` and `--help`; exit codes 0 ok, 1 strict failure, 2 error, 3 context unavailable, 130 interrupted |
| IFJ-002 | Every output (terminal, JSON, Markdown, SARIF, share card, errors) is redacted: home and user paths, user and host names, URL credentials, known token formats, secret-looking assignments |
| IFJ-003 | The scan opens only files declared in the catalog and reads no more of each than its level allows (stat, header, deep); a ledger records every access and a contract test checks it |
| IFJ-004 | The scan starts no process, writes nothing and uses no network |
| IFJ-005 | Paths of every agent resolve per system (Linux, macOS, Windows) and honour the agents' own overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `GEMINI_CLI_*`, `OPENCODE_CONFIG*`, `CURSOR_CONFIG_DIR`) |
| IFJ-006 | `.ifinjected.toml` sets which agents and checks run and accepts known risks; unknown keys are errors |

### Inventory: what exists on this machine

| ID | Requirement |
|---|---|
| IFJ-010 | SSH private keys, told apart as passphrase-protected or not from the key header, with the public fingerprint |
| IFJ-011 | Cloud credentials: AWS, Google Cloud (application default credentials, service account keys), Azure |
| IFJ-012 | Version control and registry tokens: GitHub CLI, git credential store, netrc, npm, PyPI, Cargo |
| IFJ-013 | Docker (inline auths vs a credential store) and Kubernetes (token or key data) credentials |
| IFJ-014 | Deploy, infrastructure and payment CLI tokens; password-manager sessions; browser profiles (path only) |
| IFJ-015 | The coding agents' own credentials and transcripts; `.env` files in the workspace and its parents (names only with `--include-env`) |
| IFJ-016 | Secret-looking environment variable names the agent would inherit; credential sockets (SSH agent, Docker) |

### Agents: effective policy and reachability

| ID | Requirement |
|---|---|
| IFJ-020 | Policy engine: channels (file tools, recognised and arbitrary shell, MCP, web fetch, hooks), gates (none, human, automated, denied), enforcement (OS sandbox, agent rule) and reach per item |
| IFJ-021 | A deny rule that only the agent enforces is reported as bypassable when an unsandboxed shell or subprocess can still reach the item |
| IFJ-022 | Claude Code: settings layers and precedence, trust, permission modes and rules, sandbox, hooks, MCP servers |
| IFJ-023 | Codex: config layers, profiles, sandbox modes and permission profiles, requirements, MCP servers |
| IFJ-024 | Gemini CLI: settings layers, approval modes, tool lists, policy tiers, sandbox kinds, trusted folders, MCP servers |
| IFJ-025 | Cursor: CLI permissions, sandbox.json, MCP servers |
| IFJ-026 | opencode: configuration precedence, last-match permissions, MCP servers, plugins |
| IFJ-027 | Copilot CLI: settings, approvals, sandbox, MCP servers, the Claude Code files it also loads |
| IFJ-028 | Every agent fact carries a source (URL and date); undocumented behaviour is `unknown` |

### Verdicts and output

| ID | Requirement |
|---|---|
| IFJ-030 | MCP servers classified as untrusted-input sources and exfiltration sinks from a dated, source-tagged catalog |
| IFJ-031 | Lethal trifecta per agent (private data, untrusted input, a way out), including built-in tools; verdict and an A–F grade |
| IFJ-032 | Rules with stable codes `IFJ-<FAMILY>-<NNN>`; `explain CODE` and `rules` |
| IFJ-033 | `scan` shows one block per agent; `--strict` exits 1 on failing findings |
| IFJ-034 | JSON (with a published schema), Markdown and SARIF reports; `report --output` |
| IFJ-035 | `plan`: the configuration change that closes each finding, per agent, never applied |
| IFJ-036 | Share card, share text and badge that show a grade and counts only, unless detail is asked for |

### Prove mode and CI

| ID | Requirement |
|---|---|
| IFJ-040 | `prove --run`: an open-only probe under each agent's real sandbox (`srt`, `codex sandbox`, or directly) reports claimed, proven or contradicted |
| IFJ-041 | `prove --run --network`: one connection attempt to show whether data could leave |
| IFJ-042 | `diff --base REF`: a pull request that widens agent permissions in committed configuration is flagged, with SARIF |
| IFJ-043 | A GitHub Action that runs the diff on pull requests and uploads SARIF |

## Later

- Prove mode on macOS (Seatbelt through `srt`, `codex sandbox`, Gemini's `sandbox-exec` profiles) and Windows.
- A read-only MCP server and an Agent Skill, so an agent can check itself.
- More agents: Windsurf, Cline and Roo, Continue, Zed, Amp, Goose, Kiro, Copilot agent mode in VS Code.
- `compare old.json new.json` to see what changed between two scans.
