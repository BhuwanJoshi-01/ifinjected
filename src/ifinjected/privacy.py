"""Making collected text safe to print and to share.

Everything that leaves the tool (terminal, JSON, Markdown, SARIF, share cards, error
messages) is built from redacted data: redaction runs on the whole result *before* any
renderer sees it. This is the second line of defence; the first is that no collector
keeps a secret value in the first place.
"""

from __future__ import annotations

import getpass
import re
import socket
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    from ifinjected.models import RedactionCount

T = TypeVar("T")

_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: colours, cursor movement, screen clearing
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC: window titles, hyperlinks
    r"|\x1b[@-_]"  # other two-byte escapes
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_control(text: str) -> str:
    """Remove terminal escape sequences and control characters, keeping tabs and newlines.

    Collected output can come from a broken or hostile environment; without this a
    crafted package name could rewrite the user's terminal when a report is shown.
    """
    return _CONTROL.sub("", _ESCAPE_SEQUENCE.sub("", text))


@dataclass(frozen=True, slots=True)
class RedactionContext:
    """The identifying values of the machine the report is made on."""

    home: str | None = None
    user: str | None = None
    hostname: str | None = None

    @classmethod
    def current(cls) -> RedactionContext:
        """Read the values for the current user; missing ones stay ``None``."""
        return cls(
            home=_safe(lambda: str(Path.home())),
            user=_safe(getpass.getuser),
            hostname=_safe(socket.gethostname),
        )


def _safe(read: Callable[[], str]) -> str | None:
    try:
        value = read()
    except (OSError, KeyError, RuntimeError):
        return None
    return value or None


Replacement = str | Callable[[re.Match[str]], str]

_REDACTED = "<redacted>"
_REDACTED_TOKEN = "<redacted-token>"  # noqa: S105 - the placeholder, not a token

_URL_CREDENTIALS = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s?#]*)@")
"""``scheme://user:password@`` — greedy up to the last ``@`` of the authority."""

_NAME_AND_SEPARATOR = re.compile(r"""(?<![\w-])([A-Za-z_][A-Za-z0-9_]*)(["']?\s*[=:]\s*)""")
_VALUE = re.compile(r"""("[^"]*"|'[^']*'|[^\s,;}]+)""")
"""``NAME=value``, ``name: value``, ``"name": "value"``; the name decides if it is secret."""

_SECRET_SUFFIXES = (
    "token", "secret", "password", "passwd", "apikey", "credential", "credentials", "cookie",
)  # fmt: skip
_SECRET_PARTS = frozenset({"key", "auth", "pass", "pat"})
_SESSION_NAMES = re.compile(r"(?i)^(?:BW_SESSION|OP_SESSION_\w+)$")
"""Password-manager session variables: the value unlocks the whole vault."""

_TOKENS = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub
    r"|github_pat_[A-Za-z0-9_]{22,}"
    r"|hf_[A-Za-z0-9]{30,}"  # Hugging Face
    r"|sk-[A-Za-z0-9_-]{20,}"  # OpenAI, Anthropic
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"  # AWS access key id
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
    r"|AIza[0-9A-Za-z_-]{35}"  # Google API key
    r"|ya29\.[0-9A-Za-z_-]{20,}"  # Google OAuth access token
    r"|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"  # Stripe
    r"|npm_[0-9A-Za-z]{36}"  # npm
    r"|pypi-[0-9A-Za-z_-]{50,}"  # PyPI
    r"|glpat-[0-9A-Za-z_-]{20,}"  # GitLab
    r"|gsk_[0-9A-Za-z]{40,}"  # Groq
    r")(?![A-Za-z0-9_-])"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL
)
"""A PEM or OpenSSH private key block, or the start of one cut off by a limit."""
_REDACTED_KEY = "<redacted-private-key>"
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")


def is_secret_name(name: str) -> bool:
    """``HF_TOKEN``, ``accessToken``, ``DB_PASSWORD``, ``OPENAI_API_KEY``: yes.
    ``tokenizers``, ``CUDA_HOME``, ``author``, ``KEYBOARD``: no."""
    if _SESSION_NAMES.match(name):
        return True
    parts = [part for part in name.lower().split("_") if part]
    return any(part in _SECRET_PARTS or part.endswith(_SECRET_SUFFIXES) for part in parts)


_MIN_NAME_LENGTH = 3
_GENERIC_NAMES = frozenset(
    {
        "root", "user", "admin", "guest", "localhost", "linux", "ubuntu", "debian",
        "fedora", "arch", "archlinux", "manjaro", "pop-os", "mint", "kali", "raspberrypi",
    }
)  # fmt: skip
"""Names that identify nobody and appear in ordinary text (distribution names as hosts)."""


def _word_pattern(name: str) -> re.Pattern[str] | None:
    if len(name) < _MIN_NAME_LENGTH or name.lower() in _GENERIC_NAMES:
        return None
    # Whole words only: not inside "malice" or "alice_env", not an already redacted
    # "<user>", but a sentence-ending period is fine.
    return re.compile(rf"(?<![\w.<>-]){re.escape(name)}(?![\w<>-]|\.\w)")


# Other accounts' home directories. The name may not start with "<", so already redacted
# paths are left alone.
_OTHER_HOMES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(/home/)[^/\s:'\"<>]+"), r"\1<user>"),
    (re.compile(r"(/Users/)[^/\s:'\"<>]+"), r"\1<user>"),
    (re.compile(r"([A-Za-z]:\\Users\\)[^\\\s:'\"<>]+"), r"\1<user>"),
)


class Redactor:
    """Removes identifying and secret values from text and from whole snapshots.

    One redactor is used per report; :attr:`summary` then tells how many values of each
    kind were removed, which the report shows so the user knows redaction happened.
    """

    def __init__(self, context: RedactionContext) -> None:
        self._counts: Counter[str] = Counter()
        self._steps: list[tuple[str, re.Pattern[str], Replacement]] = []
        home = context.home.rstrip("/\\") if context.home else ""
        if len(home) > 1:  # a home of "/" would redact every absolute path
            boundary = r"(?=[/\\]|$|[^\w.-])"
            self._steps.append(("home_path", re.compile(re.escape(home) + boundary), "~"))
        for pattern, replacement in _OTHER_HOMES:
            self._steps.append(("home_path", pattern, replacement))
        # Host before user: "alice-laptop" is a host name even when the user is "alice".
        for category, name, placeholder in (
            ("host_name", context.hostname, "<host>"),
            ("user_name", context.user, "<user>"),
        ):
            word = _word_pattern(name) if name else None
            if word is not None:
                self._steps.append((category, word, placeholder))

    def text(self, value: str) -> str:
        """Return ``value`` without control characters, identifying or secret values."""
        result = strip_control(value)
        result, count = _PRIVATE_KEY.subn(_REDACTED_KEY, result)
        self._counts["private_key"] += count
        result = _URL_CREDENTIALS.sub(self._url_credentials, result)
        result = self._secret_assignments(result)
        for token_pattern, placeholder in (
            (_TOKENS, _REDACTED_TOKEN),
            (_BEARER, r"\1" + _REDACTED_TOKEN),
        ):
            result, count = token_pattern.subn(placeholder, result)
            self._counts["token"] += count
        for category, pattern, replacement in self._steps:
            result, count = pattern.subn(replacement, result)
            self._counts[category] += count
        return result

    def redact(self, obj: T) -> T:
        """Return a redacted copy of ``obj``.

        Strings are redacted; dataclasses (frozen ones too), tuples, lists and dicts are
        copied with their contents redacted; enums, numbers, booleans and ``None`` are
        returned unchanged. The original object is never modified.
        """
        return cast(T, self._redact(obj))

    @property
    def summary(self) -> dict[str, int]:
        """How many values of each kind this redactor has removed so far."""
        return {category: count for category, count in self._counts.items() if count}

    def _redact(self, obj: Any) -> Any:
        if isinstance(obj, Enum):  # StrEnum members are str; keep them as they are
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if is_dataclass(obj) and not isinstance(obj, type):
            changes = {f.name: self._redact(getattr(obj, f.name)) for f in fields(obj) if f.init}
            return replace(obj, **changes)
        if isinstance(obj, tuple):
            return tuple(self._redact(item) for item in obj)
        if isinstance(obj, list):
            return [self._redact(item) for item in obj]
        if isinstance(obj, dict):
            return {self._redact(key): self._redact(item) for key, item in obj.items()}
        return obj

    def _url_credentials(self, match: re.Match[str]) -> str:
        scheme, credentials = match.group(1), match.group(2)
        if credentials == _REDACTED:
            return match.group(0)
        self._counts["url_credentials"] += 1
        return f"{scheme}{_REDACTED}@"

    def _secret_assignments(self, text: str) -> str:
        # Scanned by hand rather than with re.sub: the value of a harmless name must not be
        # consumed, or "env: DB_PASSWORD=hunter2" would hide the password inside the value
        # of "env". After a harmless name the scan resumes right after its separator.
        parts: list[str] = []
        pos = 0
        while match := _NAME_AND_SEPARATOR.search(text, pos):
            parts.append(text[pos : match.end()])
            pos = match.end()
            value = _VALUE.match(text, pos)
            if (
                value is not None
                and is_secret_name(match.group(1))
                and not value.group(0).startswith("<redacted")
            ):
                parts.append(_REDACTED)
                pos = value.end()
                self._counts["secret_value"] += 1
        parts.append(text[pos:])
        return "".join(parts)


def redacted_with_counts(
    obj: T, context: RedactionContext | None = None
) -> tuple[T, tuple[RedactionCount, ...]]:
    """``obj`` redacted for output, with a record of what was removed, sorted by kind."""
    from ifinjected.models import RedactionCount

    redactor = Redactor(context or RedactionContext.current())
    redacted = redactor.redact(obj)
    counts = tuple(RedactionCount(kind, n) for kind, n in sorted(redactor.summary.items()))
    return redacted, counts
