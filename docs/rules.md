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


# Configuration

## IFJ-CONFIG-001: Agent configuration could not be read

A configuration file of an agent exists but could not be read or understood (not
valid JSON or TOML, too large, permission denied). What the agent may do is then
uncertain: results that depend on it are marked uncertain, never safe.

Family `config`, default level `warn`.
