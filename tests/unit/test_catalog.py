"""The catalog of sensitive items: sourced, unique, and the contract for reading."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from ifinjected.files import Level
from ifinjected.inventory.catalog import CatalogError, load_catalog, parse_catalog
from tests.homes import FakeMachine


def test_every_entry_has_a_dated_https_source() -> None:
    catalog = load_catalog()
    assert catalog.retrieved
    for entry in catalog.entries:
        assert entry.sources, entry.id
        assert all(source.url.startswith("https://") for source in entry.sources)
        assert entry.why.strip(), entry.id


def test_head_entries_say_how_many_bytes() -> None:
    for entry in load_catalog().entries:
        assert (entry.level is Level.HEAD) == (entry.head_bytes is not None), entry.id


def test_declared_levels_follow_the_catalog(tmp_path: Path) -> None:
    machine = FakeMachine(tmp_path)
    p = machine.platform()
    catalog = load_catalog()
    assert catalog.declared_level(p.home / ".ssh", p, None) is Level.HEAD
    assert catalog.declared_level(p.home / ".ssh" / "id_ed25519", p, None) is Level.HEAD
    assert catalog.declared_level(p.home / ".ssh" / "id_ed25519.pub", p, None) is Level.FULL
    assert catalog.declared_level(p.home / ".bashrc", p, None) is None
    assert catalog.declared_level(tmp_path / "elsewhere" / ".ssh", p, None) is None


def _data() -> dict[str, Any]:
    return {
        "retrieved": "2026-11-05",
        "sources": {"s": {"title": "t", "url": "https://example.org"}},
        "items": [
            {
                "id": "x.y",
                "title": "X",
                "why": "because",
                "level": "stat",
                "paths": [{"base": "home", "glob": ".x"}],
                "sources": ["s"],
            }
        ],
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["sources"]["s"].update(url="http://example.org"), "https"),
        (lambda d: d["items"].append(copy.deepcopy(d["items"][0])), "duplicate"),
        (lambda d: d["items"][0].update(sources=[]), "no source"),
        (lambda d: d["items"][0].update(sources=["nope"]), "unknown sources"),
        (lambda d: d["items"][0].update(level="head"), "head_bytes"),
        (lambda d: d["items"][0]["paths"][0].update(base="etc"), "unknown base"),
    ],
)
def test_a_malformed_catalog_is_rejected(change: Any, message: str) -> None:
    data = _data()
    change(data)
    with pytest.raises(CatalogError, match=message):
        parse_catalog(data)


def test_docs_what_is_read_md_is_generated_from_the_catalog() -> None:
    from ifinjected.inventory.docs import render_what_is_read

    path = Path(__file__).parents[2] / "docs" / "what-is-read.md"
    assert path.read_text(encoding="utf-8") == render_what_is_read(), (
        "run: uv run python -m ifinjected.inventory.docs"
    )
