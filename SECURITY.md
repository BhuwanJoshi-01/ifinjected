# Security Policy

## Supported versions

Only the latest release and the `main` branch receive fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through GitHub instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/BhuwanJoshi-01/ifinjected/security/advisories/new>).

Include what you found, how to reproduce it, and the impact you expect. You will get an answer within a week,
and a fix or mitigation as soon as possible after that.

## What counts as a security problem here

`ifinjected` looks at the most sensitive places on a developer machine, and its reports end up in CI logs, SARIF
uploads, issue trackers and share cards. These are in scope:

- **A secret in any output.** A credential value, a token, a password, the value of an environment variable or of
  a `.env` entry appearing in terminal, JSON, Markdown, SARIF, a share card, a badge or an error message.
- **Reading more than declared.** Opening a file that is not in the catalog, reading more of a credential file than
  its documented level allows, or following a link to somewhere else.
- **Execution of agent configuration.** The scan never starts an MCP server, a hook, a helper command or a plugin.
  A way to make it execute something is a vulnerability.
- **Changes to the system.** A scan must write nothing except the report file the user names. `plan` never applies
  anything.
- **Network access.** Only `prove --run --network` connects anywhere, and only to the target it reports.
- **A share card that identifies you** (user name, host name, paths, secret names) without the opt-in flags.

## What it is not

`ifinjected` is a diagnostic, not a sandbox: it describes what an agent could reach, it does not stop it. A clean
report is not a guarantee; agents change their configuration formats, and not everything an agent can do is
visible in its configuration.
