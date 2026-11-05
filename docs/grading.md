# How the grade is decided

Each agent gets a grade from A to F for the workspace it was checked in; the machine's grade is the worst of them,
because an attacker uses the easiest agent. The grade is a pure function of the agent's **lethal trifecta**
(the term is [Simon Willison's](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)): an agent that can
reach private data, takes in content an attacker can write and can send data out can be made to leak the first
through the third by the second.

## The three legs

| Leg | Open when | Examples |
|---|---|---|
| **Private data** | The agent can reach a sensitive item of medium or high severity, with or without an approval | `~/.ssh/id_ed25519` through `cat`; `OPENAI_API_KEY` through `env`; `~/.aws/credentials` around a deny rule |
| **Untrusted input** | Always, for a coding agent: the repository, its issues and its dependencies are text others can write. Also its web tools and MCP servers that bring in others' content | a README with instructions for agents; a GitHub issue; a fetched web page |
| **A way out** | A shell with network access, the agent's web fetch tool (data leaves in the URL), or an MCP server that can write elsewhere | `curl`, `git push`, `WebFetch`, a GitHub server that can open issues |

Each leg is as open as its easiest member. What stands in front of a member is its **gate**: nobody, an automated
classifier (which an injection may talk its way past), a human, or a refusal.

## The grade

| Grade | Verdict | Meaning |
|---|---|---|
| **F** | Full trifecta, ungated | All three legs open and no one, not even a classifier, has to approve any step, and a high-severity item is exposed. An injected agent can leak a credential on its own. |
| **D** | Full trifecta, ungated | All three legs open with nothing but a classifier in the way, or only medium-severity items exposed. |
| **C** | Full trifecta, gated | All three legs open, but a human must approve at least one step. Safe as long as every prompt is read. |
| **B** | Two legs | One leg is closed: nothing sensitive is reachable, or there is no way out. One new MCP server or dotfile can complete it. |
| **A** | Contained | At most one leg open. |

Untrusted input is always open for a coding agent, so in practice **A** means that neither private data nor a way
out is open, and **B** that one of the two is closed.

## What the grade does not say

- It describes what the configuration allows, not what an agent will do. A grade of F is not an incident.
- A human gate is only as good as the attention it gets: approving prompts without reading them turns C into F.
- `prove --run` checks the sandbox part of the claim on this machine; the rest comes from each agent's documented
  behaviour, cited in `src/ifinjected/agents/data.json`.
