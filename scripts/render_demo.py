"""Render the README images from the messy-laptop example: the scan and the share card.

    uv run python scripts/render_demo.py

Deterministic: a fixed date and a fake machine, so the images only change when the
output does.
"""

from __future__ import annotations

import dataclasses
import io
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "messy-laptop"))

from build import build  # noqa: E402

from ifinjected.homes import Platform, System  # noqa: E402
from ifinjected.models import Policy, Snapshot  # noqa: E402
from ifinjected.orchestrator import diagnose, inspect_all  # noqa: E402
from ifinjected.privacy import RedactionContext, redacted_with_counts  # noqa: E402
from ifinjected.reports.card import render_card  # noqa: E402
from ifinjected.reports.scan import render_scan  # noqa: E402


@contextmanager
def demo_snapshot() -> Iterator[Snapshot]:
    """The messy-laptop scan with a fixed date, version and environment, redacted."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        home = build(root)
        platform = Platform(
            System.LINUX, home, env={"HOME": str(home), "OPENAI_API_KEY": "sk-proj-FAKE"}, root=root
        )
        workspace = home / "src" / "app"
        snapshot = diagnose(inspect_all(platform, Policy(), workspace))
        snapshot = dataclasses.replace(
            snapshot, created_at="2026-11-05T12:00:00Z", tool_version="0.1.0"
        )
        redacted, counts = redacted_with_counts(
            snapshot, RedactionContext(str(home), "dev", "laptop")
        )
        yield dataclasses.replace(redacted, redactions=counts)


def main() -> None:
    with demo_snapshot() as redacted:
        console = Console(
            record=True,
            width=100,
            force_terminal=True,
            color_system="truecolor",
            file=io.StringIO(),
        )
        render_scan(redacted, console)
        images = ROOT / "docs" / "images"
        images.mkdir(parents=True, exist_ok=True)
        (images / "scan.svg").write_text(console.export_svg(title="ifinjected"), encoding="utf-8")
        (images / "card.svg").write_text(render_card(redacted, detail=True), encoding="utf-8")
    print("wrote docs/images/scan.svg and docs/images/card.svg")


if __name__ == "__main__":
    main()
