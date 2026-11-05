"""Share card, share text and README badge: a grade and counts, nothing that identifies you.

Built only from the trifecta verdicts and the number of items and problems: no path, user
name, host name, secret name, key fingerprint or MCP server name can appear, whatever the
snapshot contains. ``--share-detail`` adds the *kinds* of exposed items (``SSH keys``,
``cloud credentials``), still without paths.
"""

from __future__ import annotations

from collections import Counter
from html import escape

from ifinjected.models import Snapshot, Status
from ifinjected.trifecta.verdict import Grade, machine_grade

PROJECT = "github.com/BhuwanJoshi-01/ifinjected"
_COLORS = {
    Grade.A: "#2da44e",
    Grade.B: "#57ab5a",
    Grade.C: "#d4a72c",
    Grade.D: "#e5534b",
    Grade.F: "#c93c37",
}
_VERDICTS = {
    "full_ungated": "lethal trifecta, nobody approves",
    "full_gated": "lethal trifecta, behind an approval",
    "two_legs": "one change from a trifecta",
    "contained": "contained",
}
_KINDS = {
    "ssh.key": "SSH keys", "aws.credentials": "cloud credentials", "aws.config": "cloud credentials",
    "aws.sso_cache": "cloud credentials", "gcloud.credentials": "cloud credentials",
    "gcloud.adc": "cloud credentials", "azure.tokens": "cloud credentials", "gh.hosts": "code host tokens",
    "git.credentials": "code host tokens", "netrc": "passwords", "npm.token": "package tokens",
    "pypi.token": "package tokens", "cargo.token": "package tokens", "docker.config": "registry logins",
    "kube.config": "cluster credentials", "agent.auth": "agent login tokens", "env.file": ".env files",
    "env.variables": "environment secrets", "browser.cookies": "browser sessions",
}  # fmt: skip


def _exposed_kinds(snapshot: Snapshot) -> list[str]:
    kinds: Counter[str] = Counter()
    for exposure in snapshot.exposures:
        if exposure.reach.reachable and exposure.item in _KINDS:
            kinds[_KINDS[exposure.item]] += 1
    return [kind for kind, _ in kinds.most_common(3)]


def render_card(snapshot: Snapshot, *, detail: bool = False) -> str:
    """A 1200x630 SVG card (the size social sites preview)."""
    grade = machine_grade(snapshot.trifectas)
    letter = grade.value if grade else "?"
    color = _COLORS.get(grade, "#768390") if grade else "#768390"
    problems = sum(1 for f in snapshot.findings if f.status in {Status.FAIL, Status.WARN})
    rows = []
    shown = snapshot.trifectas[: 5 if detail else 6]
    for index, trifecta in enumerate(shown):
        y = 250 + index * 52
        c = _COLORS[trifecta.grade]
        rows.append(
            f'<text x="470" y="{y}" class="agent">{escape(trifecta.agent.display_name)}</text>'
            f'<rect x="760" y="{y - 30}" width="44" height="40" rx="8" fill="{c}"/>'
            f'<text x="782" y="{y}" class="small-grade">{trifecta.grade.value}</text>'
            f'<text x="822" y="{y}" class="verdict">{escape(_VERDICTS[trifecta.verdict.value])}</text>'
        )
    if not rows:
        rows.append('<text x="470" y="250" class="agent">No coding agent found</text>')
    detail_line = ""
    if detail:
        kinds = _exposed_kinds(snapshot)
        if kinds:
            y = min(250 + len(rows) * 52 - 6, 504)
            detail_line = (
                f'<text x="470" y="{y}" class="detail">reachable: {escape(", ".join(kinds))}</text>'
            )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<style>
text {{ font-family: -apple-system, "Segoe UI", Ubuntu, Helvetica, Arial, sans-serif; fill: #e6edf3; }}
.title {{ font-size: 40px; font-weight: 700; }}
.question {{ font-size: 26px; fill: #9da7b3; }}
.grade {{ font-size: 230px; font-weight: 800; fill: #ffffff; text-anchor: middle; }}
.agent {{ font-size: 28px; font-weight: 600; }}
.small-grade {{ font-size: 26px; font-weight: 800; fill: #ffffff; text-anchor: middle; }}
.verdict {{ font-size: 22px; fill: #9da7b3; }}
.detail {{ font-size: 22px; fill: #d4a72c; }}
.foot {{ font-size: 24px; fill: #9da7b3; }}
.cmd {{ font-size: 26px; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; fill: #7ee787; }}
</style>
<rect width="1200" height="630" fill="#0d1117"/>
<text x="70" y="95" class="title">ifinjected</text>
<text x="70" y="140" class="question">If a coding agent on this machine got prompt-injected right now…</text>
<rect x="70" y="190" width="340" height="340" rx="36" fill="{color}"/>
<text x="240" y="440" class="grade">{letter}</text>
{"".join(rows)}
{detail_line}
<text x="470" y="548" class="foot">{len(snapshot.items)} sensitive items on this machine · {problems} problems</text>
<text x="70" y="592" class="cmd">$ uvx ifinjected</text>
<text x="1130" y="592" class="foot" text-anchor="end">{PROJECT}</text>
</svg>
"""


def render_share_text(snapshot: Snapshot) -> str:
    grade = machine_grade(snapshot.trifectas)
    if grade is None:
        return f"ifinjected found no coding agent on my machine. Check yours: uvx ifinjected  https://{PROJECT}\n"
    agents = ", ".join(f"{t.agent.display_name} {t.grade.value}" for t in snapshot.trifectas)
    return (
        f"If one of my coding agents got prompt-injected, what could it reach? ifinjected says {grade.value} "
        f"({agents}). Check yours, offline and read-only: uvx ifinjected  https://{PROJECT}\n"
    )


def render_badge(snapshot: Snapshot) -> str:
    """A small two-part badge, ``ifinjected | grade C``, for a README."""
    grade = machine_grade(snapshot.trifectas)
    value = f"grade {grade.value}" if grade else "no agent"
    color = _COLORS.get(grade, "#768390") if grade else "#768390"
    left, right = 74, 18 + 7 * len(value)
    width = left + right
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="ifinjected: {value}">
<title>ifinjected: {value}</title>
<rect width="{left}" height="20" fill="#30363d"/><rect x="{left}" width="{right}" height="20" fill="{color}"/>
<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
<text x="{left / 2}" y="14">ifinjected</text><text x="{left + right / 2}" y="14">{value}</text>
</g>
</svg>
"""
