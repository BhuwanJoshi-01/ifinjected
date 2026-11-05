"""SECRET: credentials on this machine, whichever agent might read them."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ifinjected.models import Confidence, Finding, SensitiveItem, Severity, Snapshot, Status
from ifinjected.rules.engine import Registry
from ifinjected.rules.shared import item_evidence, item_source

registry = Registry()

_ORDER = list(Severity)


def _findings(
    rule_id: str,
    snapshot: Snapshot,
    ids: Iterable[str],
    action: str,
    *,
    at_least: Severity = Severity.MEDIUM,
    why: str = "",
) -> Iterator[Finding]:
    wanted = set(ids)
    for item in snapshot.items:
        if item.id not in wanted or _ORDER.index(item.severity) < _ORDER.index(at_least):
            continue
        yield _finding(rule_id, item, action, why)


def _finding(rule_id: str, item: SensitiveItem, action: str, why: str) -> Finding:
    return Finding(
        rule_id,
        Status.WARN,
        item.severity,
        Confidence.HIGH,
        f"{item.title}: {item.path}",
        why or "Any process running as you, an injected agent included, can use it.",
        item=item.id,
        sources=item_source(item),
        evidence=item_evidence(item),
        recommended_action=action,
        verify_command="ifinjected inventory --deep",
    )


@registry.rule(
    "IFJ-SECRET-001",
    "An SSH key has no passphrase",
    sources=("https://man.openbsd.org/ssh-keygen",),
)
def ssh_keys(snapshot: Snapshot) -> Iterator[Finding]:
    """A private key without a passphrase: copying the file is enough to log in to every
    server and push to every Git host that trusts it. With a passphrase, the copy is
    useless without it (and ssh-agent can still hold the unlocked key for you)."""
    for item in snapshot.items:
        if item.id == "ssh.key" and item.fact("protection") == "none":
            yield _finding(
                "IFJ-SECRET-001",
                item,
                f"Add a passphrase: ssh-keygen -p -f {item.path}, and load the key into "
                "ssh-agent when you need it.",
                "Whoever copies the file can use the key; no passphrase protects it.",
            )


@registry.rule(
    "IFJ-SECRET-002",
    "Long-lived cloud credentials are on disk",
    sources=("https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",),
)
def cloud(snapshot: Snapshot) -> Iterator[Finding]:
    """Cloud credentials that work from anywhere for a long time: AWS static access keys,
    gcloud's refresh tokens and application default credentials, Azure CLI tokens and
    service principal secrets. Short-lived, SSO-based credentials limit what a copy is
    worth."""
    yield from _findings(
        "IFJ-SECRET-002",
        snapshot,
        (
            "aws.credentials",
            "aws.config",
            "aws.sso_cache",
            "gcloud.credentials",
            "gcloud.adc",
            "azure.tokens",
        ),
        "Prefer short-lived credentials (aws sso login, workload identity), and delete static "
        "keys you no longer need.",
    )


@registry.rule(
    "IFJ-SECRET-003",
    "A code or package registry token is on disk",
    sources=("https://git-scm.com/docs/git-credential-store",),
)
def vcs(snapshot: Snapshot) -> Iterator[Finding]:
    """Tokens that push code or publish packages under your name: the GitHub CLI's
    login, git's plain-text credential store, netrc, npm, PyPI and Cargo tokens. One of
    them in the wrong hands is a supply-chain attack on everyone who installs your
    packages."""
    yield from _findings(
        "IFJ-SECRET-003",
        snapshot,
        ("gh.hosts", "git.credentials", "netrc", "npm.token", "pypi.token", "cargo.token"),
        "Keep tokens in the system keyring (gh does by default), use short-lived or "
        "trusted-publishing tokens for releases, and remove plain-text stores.",
    )


@registry.rule(
    "IFJ-SECRET-004",
    "Container or cluster credentials are on disk",
    sources=("https://docs.docker.com/reference/cli/docker/login/#credential-stores",),
)
def containers(snapshot: Snapshot) -> Iterator[Finding]:
    """Docker registry passwords kept inline in ``config.json`` (only base64-encoded) and
    kubeconfig files with tokens or client keys: push images and act on clusters as
    you."""
    yield from _findings(
        "IFJ-SECRET-004",
        snapshot,
        ("docker.config", "kube.config"),
        "Configure a Docker credential store (credsStore) and prefer exec-based kubeconfig "
        "credentials that expire.",
    )


@registry.rule(
    "IFJ-SECRET-005",
    "A developer service token is on disk",
    sources=(
        "https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables",
    ),
)
def services(snapshot: Snapshot) -> Iterator[Finding]:
    """Tokens of developer services kept in well-known files: Hugging Face, Supabase,
    Terraform Cloud, Vault."""
    yield from _findings(
        "IFJ-SECRET-005",
        snapshot,
        ("huggingface.token", "supabase.token", "terraform.token", "vault.token"),
        "Scope the token to what you need, and log out of services you no longer use.",
    )


@registry.rule("IFJ-SECRET-006", "A coding agent's own login token is on disk")
def agent_tokens(snapshot: Snapshot) -> Iterator[Finding]:
    """The coding agents' own credentials. An injected agent can send its token away and
    the attacker keeps using your subscription or API key from anywhere."""
    yield from _findings(
        "IFJ-SECRET-006",
        snapshot,
        ("agent.auth",),
        "Prefer the system keychain where the agent supports it, and revoke tokens of agents "
        "you no longer use.",
    )


@registry.rule("IFJ-SECRET-007", "A .env file holds application secrets")
def env_files(snapshot: Snapshot) -> Iterator[Finding]:
    """A ``.env`` file in the workspace, a subdirectory or a directory above it. Coding
    agents read project files freely, and ``.gitignore`` does not stop them."""
    yield from _findings(
        "IFJ-SECRET-007",
        snapshot,
        ("env.file",),
        "Deny .env files in the agent's rules and sandbox, or load secrets at run time from a "
        "secret manager instead of a file in the project.",
    )


@registry.rule(
    "IFJ-SECRET-008",
    "Browser session cookies can be copied",
    sources=("https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data",),
)
def browsers(snapshot: Snapshot) -> Iterator[Finding]:
    """A browser profile's cookie database. Copied, it signs in to every site you are
    signed in to, without a password or a second factor. Firefox keeps cookies
    unencrypted; Chrome and Chromium encrypt them with a key your user can read."""
    yield from _findings(
        "IFJ-SECRET-008",
        snapshot,
        ("browser.cookies",),
        "Deny the browser profile directories in the agent's sandbox (denyRead).",
    )


@registry.rule("IFJ-SECRET-009", "A password manager is usable without a prompt")
def password_managers(snapshot: Snapshot) -> Iterator[Finding]:
    """A password manager that any process running as you can use while it is unlocked:
    ``pass`` while gpg-agent holds the key, the 1Password CLI while the app is unlocked.
    One command lists every password you have."""
    yield from _findings(
        "IFJ-SECRET-009",
        snapshot,
        ("pass.store", "onepassword.cli"),
        "Lower gpg-agent's cache time, require approval for each 1Password CLI access, and "
        "deny the store directories in the agent's sandbox.",
    )


@registry.rule("IFJ-SECRET-010", "Secrets are in the environment")
def environment(snapshot: Snapshot) -> Iterator[Finding]:
    """Variables whose names say they hold a credential are in the environment the agent
    inherits. Every command it runs gets them, and one ``env`` prints them all; no file
    rule applies to the environment."""
    yield from _findings(
        "IFJ-SECRET-010",
        snapshot,
        ("env.variables",),
        "Start agents from a shell without these variables, or have the sandbox strip them "
        "(Claude Code: sandbox credentials.envVars with mode deny).",
    )


@registry.rule(
    "IFJ-SECRET-011",
    "A credential can be used without being read",
    sources=("https://docs.docker.com/engine/security/#docker-daemon-attack-surface",),
)
def sockets(snapshot: Snapshot) -> Iterator[Finding]:
    """A socket lets any process running as you use a credential it cannot read:
    ssh-agent signs with every loaded key, gpg-agent decrypts while a passphrase is
    cached, and a Docker socket you can write to is root on the machine."""
    yield from _findings(
        "IFJ-SECRET-011",
        snapshot,
        ("socket.ssh_agent", "socket.docker", "socket.gpg_agent"),
        "Use ssh-agent confirmation (ssh-add -c) for important keys, rootless Docker instead "
        "of the docker group, and keep agents from reaching these sockets.",
        at_least=Severity.LOW,
    )


@registry.rule("IFJ-SECRET-012", "A credential file is readable by other users")
def readable_by_others(snapshot: Snapshot) -> Iterator[Finding]:
    """The file's permission bits let other users on this machine read it, not only you."""
    for item in snapshot.items:
        if item.readable_by_others:
            yield Finding(
                "IFJ-SECRET-012",
                Status.WARN,
                Severity.MEDIUM,
                Confidence.HIGH,
                f"{item.title} is readable by other users: {item.path}",
                "Group or other read permission is set on a credential file.",
                item=item.id,
                sources=item_source(item),
                recommended_action=f"chmod 600 {item.path}",
                verify_command="ifinjected inventory",
            )
