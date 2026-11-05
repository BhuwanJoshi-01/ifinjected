"""What an agent inherits without reading any file: environment variables and sockets.

An agent started from this shell gets its environment. Variables whose *names* say they
hold a secret are listed by name; their values are never looked at. Sockets let a
process *use* a credential without reading it: ssh-agent signs with every loaded key,
gpg-agent decrypts while it caches a passphrase, and a writable Docker socket is root on
the machine.

The environment is this process's own. An agent started from an IDE, a desktop launcher
or a service manager may see a different one; the report says so.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ifinjected.files import Kind, stat_entry
from ifinjected.homes import Platform, System
from ifinjected.inventory.base import Collected, Context
from ifinjected.models import Evidence, SensitiveItem, Severity
from ifinjected.privacy import is_secret_name

_KNOWN_PROVIDERS = re.compile(
    r"^(?:"
    r"AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_KEY_ID)"
    r"|(?:GH|GITHUB|GITLAB|GL)_TOKEN|GITHUB_PAT|GH_ENTERPRISE_TOKEN"
    r"|(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE|GROQ|MISTRAL|COHERE|DEEPSEEK|XAI|OPENROUTER|TOGETHER)_API_KEY"
    r"|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|TWINE_PASSWORD"
    r"|CARGO_REGISTRY_TOKEN|VAULT_TOKEN|STRIPE_(?:SECRET_)?(?:API_)?KEY|SLACK_(?:BOT_)?TOKEN"
    r"|AZURE_CLIENT_SECRET|DATABASE_URL|DIGITALOCEAN_(?:ACCESS_)?TOKEN|CLOUDFLARE_API_TOKEN"
    r"|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|SUPABASE_ACCESS_TOKEN|FLY_API_TOKEN|DOCKER_PASSWORD"
    r"|BW_SESSION|OP_SESSION_\w+|OP_SERVICE_ACCOUNT_TOKEN"
    r")$"
)
"""Names that are a live credential for a known service, not just secret-looking."""

_NOT_SECRETS = re.compile(
    r"(?:_SOCK|_SOCKET|_PID|_PATH|_FILE|_DIR|_HOME|_URL_BASE)$|^GOOGLE_APPLICATION_CREDENTIALS$"
)
"""Variables that *point at* a credential (a socket, a file) rather than hold one. Files
and sockets are reported where they are found."""

ENVIRONMENT = "environment of this shell"
"""The ``path`` of items that live in the environment, not in a file."""

_DATABASE_URLS = re.compile(r"^(?:DATABASE|POSTGRES|MYSQL|MONGO(?:DB)?|REDIS)_URL$")


def secret_variable_names(env: dict[str, str] | os._Environ[str]) -> tuple[list[str], list[str]]:
    """(known provider credentials, other secret-looking names), each sorted. Only the
    names are looked at, never the values."""
    known, other = [], []
    for name in env:
        upper = name.upper()
        if _KNOWN_PROVIDERS.match(upper) or _DATABASE_URLS.match(upper):
            known.append(name)
        elif is_secret_name(name) and not _NOT_SECRETS.search(upper):
            other.append(name)
    return sorted(known), sorted(other)


def _variables(p: Platform) -> Collected:
    found = Collected()
    known, other = secret_variable_names(dict(p.env))
    if known:
        found.items.append(
            SensitiveItem(
                id="env.variables",
                title="Service credentials in the environment",
                path=ENVIRONMENT,
                severity=Severity.HIGH,
                facts=(Evidence("environment", "variables", ", ".join(known)),),
            )
        )
    if other:
        found.items.append(
            SensitiveItem(
                id="env.variables",
                title="Secret-looking variables in the environment",
                path=ENVIRONMENT,
                severity=Severity.MEDIUM,
                facts=(Evidence("environment", "variables", ", ".join(other)),),
            )
        )
    credentials = p._env_path("GOOGLE_APPLICATION_CREDENTIALS")
    if credentials is not None and stat_entry(credentials).kind is Kind.FILE:
        found.items.append(
            SensitiveItem(
                id="env.variables",
                title="Google service account key (named by GOOGLE_APPLICATION_CREDENTIALS)",
                path=str(credentials),
                severity=Severity.HIGH,
            )
        )
    return found


def docker_sockets(p: Platform) -> list[Path]:
    if p.system is System.WINDOWS:
        return []
    sockets = [p.system_path("/var/run/docker.sock"), p.system_path("/run/docker.sock")]
    sockets.append(p.home / ".docker" / "run" / "docker.sock")
    host = (p.env_value("DOCKER_HOST") or "").strip()
    if host.startswith("unix://"):
        sockets.insert(0, Path(host.removeprefix("unix://")))
    return sockets


def gpg_agent_sockets(p: Platform) -> list[Path]:
    sockets = [p.home / ".gnupg" / "S.gpg-agent"]
    runtime = p._env_path("XDG_RUNTIME_DIR")
    if runtime is not None:
        sockets.insert(0, runtime / "gnupg" / "S.gpg-agent")
    return sockets


def _usable(path: Path) -> bool:
    """A socket this user may connect to: it exists and is readable and writable.

    ``os.access`` asks the kernel about permissions; nothing is connected to.
    """
    info = stat_entry(path)
    return info.kind is Kind.OTHER and os.access(path, os.R_OK | os.W_OK)


def _sockets(p: Platform) -> Collected:
    found = Collected()
    ssh = p._env_path("SSH_AUTH_SOCK")
    if ssh is not None and _usable(ssh):
        found.items.append(
            SensitiveItem(
                id="socket.ssh_agent",
                title="ssh-agent (signs with every key loaded into it)",
                path=str(ssh),
                severity=Severity.MEDIUM,
            )
        )
    for path in dict.fromkeys(docker_sockets(p)):
        if _usable(path):
            found.items.append(
                SensitiveItem(
                    id="socket.docker",
                    title="Docker socket you can write to (root on this machine)",
                    path=str(path),
                    severity=Severity.HIGH,
                )
            )
            break
    for path in gpg_agent_sockets(p):
        if _usable(path):
            found.items.append(
                SensitiveItem(
                    id="socket.gpg_agent",
                    title="gpg-agent (decrypts while it caches a passphrase)",
                    path=str(path),
                    severity=Severity.LOW,
                )
            )
            break
    return found


def collect_environment(context: Context) -> Collected:
    found = _variables(context.platform)
    found.extend(_sockets(context.platform))
    return found
