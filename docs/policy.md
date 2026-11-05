# The policy file: `.ifinjected.toml`

A project says what it accepts in `.ifinjected.toml` at the top of the workspace. The file is optional: without
it the built-in defaults below apply, and `ifinjected` still reports everything it finds. There is no user-wide
policy, so a CI job and a developer get the same answer for the same repository.

```toml
schema_version = 1

[scan]
agents = ["claude_code", "codex"]   # only these agents (default: every agent found)
deep = false                        # parse credential files for structure: profile and host names, never values
include_env = false                 # list the variable names in .env files (never their values)
max_file_bytes = 1048576            # configuration files larger than this are refused and reported

[policy]                            # allow | warn | deny, per rule family
read = "deny"
trifecta = "deny"
secret = "warn"

[accept]
items = ["ssh.key"]                 # catalog items you knowingly let agents reach
mcp_servers = ["github"]            # MCP servers you trust as input and as a way out
hosts = ["github.com"]              # network destinations you accept as ways out
```

Check what applies with:

```bash
ifinjected policy                   # this workspace's file, or the defaults
ifinjected policy --workspace PATH
```

Each value the file changes is listed next to the default it replaces.

## Levels

| Level | Meaning |
| --- | --- |
| `allow` | Reported as information. Never fails a run. |
| `warn` | Reported as a warning. `--strict` does not fail on it. |
| `deny` | Reported as a failure, and `--strict` exits with 1. |

## Families

Every finding code names its family: `IFJ-READ-003` is in `read`.

| Key | Findings about | Default |
| --- | --- | --- |
| `posture` | How an agent is set up: approvals off, no OS sandbox, escape hatches, missing trust gates. | `warn` |
| `read` | Credentials an agent can read without approval, or around a deny rule. | `deny` |
| `secret` | Credentials on this machine, whichever agent might read them (unencrypted keys, static cloud keys). | `warn` |
| `input` | Untrusted content an agent takes in: web pages, issues, mail. | `warn` |
| `exfil` | Ways data could leave: open network, fetches, MCP servers that write elsewhere, publishing. | `warn` |
| `mcp` | MCP servers that run unsandboxed, are fetched unpinned or are auto-approved. | `warn` |
| `hook` | Hooks and helper commands that run outside the sandbox. | `warn` |
| `trifecta` | One agent with private data, untrusted input and a way out. | `deny` |
| `prove` | The probe contradicted what the configuration claims. | `deny` |
| `diff` | A change to committed agent configuration that widens what agents may do. | `deny` |
| `config` | Agent configuration that could not be read or understood. | `warn` |

## What makes a file invalid

The file is TOML read as data; nothing in it is run. `ifinjected` refuses to use it, exits with 2 and names the
problem when:

- `schema_version` is missing or not `1`;
- a section or key is unknown (a misspelt key must not quietly fall back to a default);
- a value has the wrong type, a level is not `allow`, `warn` or `deny`, or an agent is not one of
  `claude_code`, `codex`, `gemini_cli`, `cursor`, `opencode`, `copilot_cli`;
- a name in `[accept]` is not a plain name (item ids are lower case with dots, hosts may start with `*.`);
- the file is larger than 64 KiB, is not a regular file, or is a link to somewhere outside the workspace.

## Accepting a risk

An accepted item, MCP server or host is still reported, marked as accepted, so the report stays complete. Its
findings pass instead of warning or failing. Accept what you have decided to live with, for example a GitHub
token every agent needs to push, not what you have not looked at yet.
