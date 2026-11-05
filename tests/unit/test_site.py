"""The project page: its listing is what the tool reports, and it loads nothing from elsewhere."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]
SITE = ROOT / "site"


def _render_site() -> ModuleType:
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "render_site", ROOT / "scripts" / "render_site.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(sys.platform == "win32", reason="the example is a Linux laptop")
def test_the_listing_is_what_scan_reports_on_the_example() -> None:
    render = _render_site()
    page = (SITE / "index.html").read_text(encoding="utf-8")
    with render.demo_snapshot() as snapshot:
        expected = render.replace_listing(page, render.render_listing(snapshot))
    assert page == expected, "run: uv run python scripts/render_site.py"


def test_the_page_loads_only_its_own_files() -> None:
    page = (SITE / "index.html").read_text(encoding="utf-8")
    style = (SITE / "style.css").read_text(encoding="utf-8")
    loaded = re.findall(r'<(?:link|script|img)[^>]+(?:href|src)="([^"]+)"', page)
    loaded += re.findall(r'url\("([^"]+)"\)', style)
    local = [ref for ref in loaded if not ref.startswith("https://bhuwanjoshi-01.github.io/")]
    assert local
    for ref in local:
        assert "://" not in ref, ref
        assert (SITE / ref).is_file(), ref


def test_every_font_comes_with_its_license() -> None:
    fonts = SITE / "assets" / "fonts"
    assert sorted(p.name for p in fonts.glob("OFL-*.txt")) == [
        "OFL-IBMPlexMono.txt",
        "OFL-Newsreader.txt",
    ]
