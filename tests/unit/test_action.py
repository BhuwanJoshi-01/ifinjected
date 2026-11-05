"""The GitHub Action's contract: inputs, outputs, and that it installs from its own tag."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]


def _run_blocks(action: str) -> list[str]:
    """The shell lines of every ``run: |`` block."""
    blocks: list[str] = []
    indent: int | None = None
    for line in action.splitlines():
        if line.strip().startswith("run: |"):
            indent = len(line) - len(line.lstrip())
            continue
        if indent is not None:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                indent = None
            else:
                blocks.append(line)
    return blocks


def test_the_action_runs_diff_from_its_own_checkout() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "using: composite" in action
    assert 'uvx --quiet --from "$GITHUB_ACTION_PATH" ifinjected' in action
    for name in ("base:", "strict:", "sarif:", "working-directory:"):
        assert name in action


def test_inputs_reach_the_scripts_through_env_only() -> None:
    lines = _run_blocks((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert lines
    assert not [line for line in lines if "${{" in line]


def test_the_self_test_covers_a_widening_and_a_quiet_change() -> None:
    workflow = (ROOT / ".github" / "workflows" / "action.yml").read_text(encoding="utf-8")
    assert "uses: ./" in workflow
    assert "IFJ-DIFF-003" in workflow
