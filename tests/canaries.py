"""Fake secrets planted in fake homes. None of them may ever reach any output.

Every canary contains :data:`MARK`, so a contract test can check a whole report with one
search. Some are shaped like real tokens (so the redactor would catch them too) and some
are not (so only "never kept in the first place" protects them).
"""

from __future__ import annotations

MARK = "Zq8Canary"

SSH_KEY_BODY = f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ{MARK}AAAAAAAAB"
AWS_ACCESS_KEY_ID = "AKIAZQ8CANARY0000000"
AWS_SECRET = f"wJalrXUtnFEMI/K7MDENG/{MARK}bPxRfiCYEXAMPLEKEY"
GH_TOKEN = "ghp_" + MARK + "0" * (36 - len(MARK))
NPM_TOKEN = "npm_" + MARK + "1" * (36 - len(MARK))
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc" + MARK + "2" * 40
ANTHROPIC_KEY = f"sk-ant-api03-{MARK}-3333333333333333333333"
OPENAI_KEY = f"sk-proj-{MARK}4444444444444444444444"
GOOGLE_REFRESH = f"1//0g{MARK}5555-refresh"
ENV_VALUE = f"plain-{MARK}-value"
"""A value without any token shape: only the parsers dropping it protects it."""
MCP_ENV_VALUE = f"mcp-{MARK}-literal"
DOCKER_AUTH = f"dXNlcjp{MARK}wYXNz"
KUBE_TOKEN = f"kube-{MARK}-bearer"
NETRC_PASSWORD = f"netrc-{MARK}-pw"
SESSION = f"bw-{MARK}-session"

ALL = (
    SSH_KEY_BODY,
    AWS_SECRET,
    GH_TOKEN,
    NPM_TOKEN,
    PYPI_TOKEN,
    ANTHROPIC_KEY,
    OPENAI_KEY,
    GOOGLE_REFRESH,
    ENV_VALUE,
    MCP_ENV_VALUE,
    DOCKER_AUTH,
    KUBE_TOKEN,
    NETRC_PASSWORD,
    SESSION,
)

USER = "alice"
HOST = "alice-mbp"
