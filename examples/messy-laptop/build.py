"""Build a fake developer machine to try ifinjected on, without touching your own.

    uv run python examples/messy-laptop/build.py /tmp/messy
    HOME=/tmp/messy/home/dev ifinjected scan --workspace /tmp/messy/home/dev/src/app

Every credential in it is fake. It has what a typical laptop has: an SSH key without a
passphrase, AWS keys, a GitHub CLI token in plain text, a .env file, and three coding
agents with their default settings (Claude Code, Codex, opencode).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FAKE = "FAKE-not-a-real-credential"
OPENSSH_HEADER = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    f"{FAKE}\n-----END OPENSSH PRIVATE KEY-----\n"
)


def build(root: Path) -> Path:
    home = root / "home" / "dev"
    files = {
        ".ssh/id_ed25519": OPENSSH_HEADER,
        ".aws/credentials": (
            f"[default]\naws_access_key_id = AKIA{FAKE[:16].upper()}\n"
            f"aws_secret_access_key = {FAKE}\n"
        ),
        ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {FAKE}\n    user: dev\n",
        ".npmrc": f"//registry.npmjs.org/:_authToken={FAKE}\n",
        ".claude/settings.json": json.dumps(
            {"permissions": {"deny": ["Read(~/.ssh/**)"], "allow": ["Bash(npm run *)"]}}, indent=2
        ),
        ".claude/.credentials.json": "{}",
        ".claude.json": json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE},
                    }
                }
            }
        ),
        ".codex/config.toml": 'model = "gpt-5.5"\n',
        ".codex/auth.json": "{}",
        ".config/opencode/opencode.json": json.dumps(
            {"$schema": "https://opencode.ai/config.json"}
        ),
        "src/app/.env": f"DATABASE_URL=postgres://app:{FAKE}@localhost/app\nSTRIPE_SECRET_KEY={FAKE}\n",
        "src/app/package.json": json.dumps({"name": "app", "scripts": {"test": "vitest"}}),
    }
    for relative, content in files.items():
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)  # as the tools that write these files do
    return home


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "messy-laptop")
    print(build(target))
