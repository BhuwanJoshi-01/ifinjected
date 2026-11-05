"""Render the listing on the project page from the messy-laptop example.

    uv run python scripts/render_site.py

The table between the ``listing`` markers in site/index.html is what ``ifinjected scan``
finds on the example laptop (the same fixed snapshot as the README images), so the page
never shows a reach the tool does not report. tests/unit/test_site.py fails when the two
differ.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_demo import demo_snapshot  # noqa: E402

from ifinjected.inventory.environment import ENVIRONMENT  # noqa: E402
from ifinjected.models import Reach, Snapshot  # noqa: E402
from ifinjected.policy.model import Gate  # noqa: E402

PAGE = ROOT / "site" / "index.html"
START, END = "<!-- listing:start -->", "<!-- listing:end -->"

# The rows in the order a reader recognises them; anything else follows.
_ORDER = (
    "ssh.key",
    "aws.credentials",
    "gh.hosts",
    "npm.token",
    "env.file",
    "env.variables",
    "agent.auth",
)

_REACH = {
    Reach.NO_APPROVAL: ("none", "no approval"),
    Reach.BYPASSABLE_RULE: ("none", "around a deny rule"),
    Reach.AFTER_APPROVAL: ("human", "after approval"),
    Reach.BLOCKED_BY_RULE: ("blocked", "blocked by a rule"),
    Reach.BLOCKED_BY_SANDBOX: ("blocked", "blocked by the sandbox"),
}
_GATE = {
    Gate.NONE: ("none", "no approval"),
    Gate.AUTOMATED: ("auto", "a classifier decides"),
    Gate.HUMAN: ("human", "after approval"),
    Gate.DENIED: ("blocked", "blocked"),
}


def _e(text: str) -> str:
    return html.escape(text, quote=True)


def _mark(kind: str, label: str, note: str | None = None, delay: int = 0) -> str:
    out = f'<mark class="hl hl-{kind}" style="--i:{delay}">{_e(label)}</mark>'
    if note:
        out += f"<small>{_e(note)}</small>"
    return out


def _subtitle(snapshot: Snapshot, agent: object) -> str:
    report = next(a for a in snapshot.agents if a.agent is agent)
    sandbox = report.policy.sandbox.enabled if report.policy else False
    mode = "default settings" if report.mode in {None, "default"} else report.mode
    return f"{mode}, {'sandbox on' if sandbox else 'no sandbox'}"


def render_listing(snapshot: Snapshot) -> str:
    trifectas = {t.agent: t for t in snapshot.trifectas}
    agents = [a.agent for a in snapshot.agents if a.found and a.agent in trifectas]
    titles = {(i.id, i.path): i.title for i in snapshot.items}
    reach = {(e.agent, e.item, e.path): e for e in snapshot.exposures}
    rows = sorted(
        {(e.item, e.path) for e in snapshot.exposures if not e.item.startswith("socket.")},
        key=lambda row: (_ORDER.index(row[0]) if row[0] in _ORDER else len(_ORDER), row[1]),
    )
    out = ['<table class="listing-table">', "<thead><tr>", '<th scope="col">On this laptop</th>']
    for agent in agents:
        out.append(
            f'<th scope="col">{_e(agent.display_name)}'
            f"<small>{_e(_subtitle(snapshot, agent))}</small></th>"
        )
    out += ["</tr></thead>", "<tbody>"]
    for index, (item, path) in enumerate(rows):
        where = "the shell's environment" if path == ENVIRONMENT else path
        cell = f"<code>{_e(where)}</code>" if path != ENVIRONMENT else _e(where)
        out.append(
            f'<tr><th scope="row">{cell}<small>{_e(titles.get((item, path), item))}</small></th>'
        )
        for agent in agents:
            name = _e(agent.display_name)
            exposure = reach.get((agent, item, path))
            if exposure is None or exposure.reach not in _REACH:
                out.append(
                    f'<td data-agent="{name}"><span class="hl-not">not reachable</span></td>'
                )
                continue
            kind, label = _REACH[exposure.reach]
            note = None
            if exposure.reach is Reach.BYPASSABLE_RULE and exposure.bypassed_pattern:
                note = (
                    f"the deny rule for {exposure.bypassed_pattern} does not cover shell commands"
                )
            out.append(f'<td data-agent="{name}">{_mark(kind, label, note, index)}</td>')
        out.append("</tr>")
    out.append(
        '<tr class="way-out"><th scope="row">Send it out'
        "<small>a way to get data off the machine</small></th>"
    )
    for agent in agents:
        name = _e(agent.display_name)
        leg = trifectas[agent].exfil
        easiest = min(leg.members, key=lambda m: list(_GATE).index(m.gate), default=None)
        if easiest is None:
            out.append(f'<td data-agent="{name}"><span class="hl-not">no way out</span></td>')
            continue
        kind, label = _GATE[easiest.gate]
        out.append(f'<td data-agent="{name}">{_mark(kind, label, easiest.what, len(rows))}</td>')
    out.append("</tr>")
    out.append('<tr class="grade"><th scope="row">Grade</th>')
    for agent in agents:
        name = _e(agent.display_name)
        grade = trifectas[agent].grade.value
        out.append(f'<td data-agent="{name}"><span class="ring">{grade}</span></td>')
    out += ["</tr>", "</tbody>", "</table>"]
    return "\n".join(out)


def replace_listing(page: str, listing: str) -> str:
    pattern = re.compile(re.escape(START) + ".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(page):
        raise SystemExit(f"{PAGE} has no {START} … {END} markers")
    return pattern.sub(lambda _: f"{START}\n{listing}\n{END}", page)


def main() -> None:
    with demo_snapshot() as snapshot:
        listing = render_listing(snapshot)
    PAGE.write_text(replace_listing(PAGE.read_text(encoding="utf-8"), listing), encoding="utf-8")
    print("wrote the listing in site/index.html")


if __name__ == "__main__":
    main()
