# Command line

`ifinjected` with no command runs `scan`. Every command is read-only and offline, except
`prove --run` (a fixed probe; one TCP connection with `--network`) and `diff` (read-only
`git`). Nothing is written except a file you name with `--output`.

Exit codes: `0` done, `1` a failing finding under `--strict`, `2` a usage or policy
error, `3` the context could not be read (an unknown git ref, a sandbox that would not
run), `130` interrupted.

This file is generated from the command line
(`uv run python -m ifinjected.clidocs`); a test fails when the two differ.

## `ifinjected scan`

What could a prompt-injected agent reach here? A grade per agent, then the fixes.

Read-only and offline: configuration is read as data, credentials are found by
location and header only, nothing is run, written or sent. Exits with 1 under
--strict when a finding fails the policy in .ifinjected.toml.

```text
ifinjected scan [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--strict` |  | Exit with 1 when a finding fails under the policy. |
| `--all` |  | List every warning instead of folding them per rule. |
| `--deep` |  | Also parse credential files for their structure (profile and host names); values are dropped while parsing and never shown. |
| `--include-env` |  | List the variable names in .env files (never their values). |
| `--agent` `AGENT` |  | Only this agent (repeat for several). Default: every agent found. One of: `claude_code`, `codex`, `gemini_cli`, `cursor`, `opencode`, `copilot_cli`. |
| `--format`, `-f` `FORMAT` | `terminal` | The output format. One of: `terminal`, `json`, `markdown`, `sarif`. |

## `ifinjected inventory`

List the credentials and other sensitive items that exist on this machine.

Found by location, permissions and file header only: a credential's value is never
read, kept or shown. This is what any agent running as you could start from.

```text
ifinjected inventory [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--deep` |  | Also parse credential files for their structure (profile and host names); values are dropped while parsing and never shown. |
| `--include-env` |  | List the variable names in .env files (never their values). |

## `ifinjected agents`

Show how each coding agent is configured for this workspace, layer by layer.

Settings files are read as data, never run: the permission mode, how each way of
reading a file is gated, the read rules with the line they come from, the sandbox,
and the MCP servers and hooks the agent would start.

```text
ifinjected agents [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--agent` `AGENT` |  | Only this agent (repeat for several). Default: every agent found. One of: `claude_code`, `codex`, `gemini_cli`, `cursor`, `opencode`, `copilot_cli`. |

## `ifinjected plan`

Show the configuration changes that close each agent's exposures. Applies nothing.

```text
ifinjected plan [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--format`, `-f` `FORMAT` | `text` | The output format. One of: `text`, `json`. |

## `ifinjected prove`

Check the claims against this machine: open credential files under Codex's sandbox.

A fixed probe calls open() and close() on each credential's path, never read(),
once directly and once inside the sandbox (codex sandbox --). With --network it
makes one TCP connection to --target and sends nothing. Other agents' sandboxes
cannot be run from outside yet; their results stay claimed.

```text
ifinjected prove [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--run` |  | Run the probe (without it, only explain). |
| `--network` |  | Also try one TCP connection from inside the sandbox. |
| `--target` `HOST:PORT` | `example.com:443` | Where --network connects. |
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |

## `ifinjected diff`

Does a change widen what coding agents may do? For pull requests.

Compares the agent configuration the repository commits (.claude/settings.json,
.mcp.json, .codex/config.toml, .gemini/settings.json, .cursor/, opencode.json,
.github/copilot/) between two refs, with read-only git. Exits with 3 when a ref
cannot be read, and with 1 under --strict when a change fails the policy.

```text
ifinjected diff [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--base` `REF` |  | The ref to compare with (e.g. origin/main). |
| `--head` `REF` | `HEAD` | The ref with the change. |
| `--repo` `PATH` | `.` | The repository (default: here). |
| `--format`, `-f` `FORMAT` | `terminal` | The output format. One of: `terminal`, `json`, `markdown`, `sarif`. |
| `--strict` |  | Exit with 1 when a finding fails under the policy. |

## `ifinjected report`

Write a redacted report (Markdown, JSON or SARIF) to a file you name.

The only command that writes anything, and only the file given with --output; an
existing file is kept unless --force is given.

```text
ifinjected report [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` `FILE` |  | Where to write; - for stdout. |
| `--format`, `-f` `FORMAT` | `markdown` | The output format. One of: `markdown`, `json`, `sarif`. |
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--deep` |  | Also parse credential files for their structure (profile and host names); values are dropped while parsing and never shown. |
| `--include-env` |  | List the variable names in .env files (never their values). |
| `--force` |  | Overwrite an existing file. |

## `ifinjected card`

A share card (SVG, 1200x630): your grade per agent and counts, nothing else.

No path, user name, host name, secret name or server name is on it.

```text
ifinjected card [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` `FILE` |  | Write here instead of printing. |
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--share-detail` |  | Also name the kinds of exposed items (no paths). |
| `--force` |  | Overwrite an existing file. |

## `ifinjected share`

One line to post with your card: the grades, and how to check yours.

```text
ifinjected share [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |

## `ifinjected badge`

A small README badge (SVG) with the grade.

```text
ifinjected badge [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` `FILE` |  | Write here instead of printing. |
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
| `--force` |  | Overwrite an existing file. |

## `ifinjected explain`

Explain a finding: what it means, why it matters, and its sources.

```text
ifinjected explain CODE
```

| Option | Default | Meaning |
|---|---|---|
| `CODE` |  | A finding code, e.g. IFJ-READ-003. |

## `ifinjected rules`

List every rule with its code and title.

```text
ifinjected rules
```

## `ifinjected policy`

Show the policy that applies: .ifinjected.toml in the workspace, or the defaults.

The file is read as data, never run. A file that cannot be used is reported with the
key at fault and exits with code 2.

```text
ifinjected policy [OPTIONS]
```

| Option | Default | Meaning |
|---|---|---|
| `--workspace` `PATH` | `.` | The project the agents work in; its .ifinjected.toml and project settings are read (default: here). |
