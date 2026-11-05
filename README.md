# ifinjected

**What could a prompt-injected coding agent reach on your machine?**

Work in progress. `ifinjected` will read the configuration of Claude Code, Codex, Gemini CLI, Cursor, opencode
and Copilot CLI, find the credentials that exist on this machine, and tell you, per agent, what an injected
agent could read and where it could send it. Read-only, offline, and it never prints a secret.
