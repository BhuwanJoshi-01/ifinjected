"""Parsing .env files as data: no expansion, nothing run (WTS-003)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.fakes import read_fixture


def _parse(text: str) -> dict[str, tuple[str, int, bool]]:
    from ifinjected.parsers.dotenv import parse_dotenv

    return {e.key: (e.value, e.line, e.reference) for e in parse_dotenv(text)}


def test_the_example_file() -> None:
    entries = _parse(read_fixture("env", "example.env"))
    assert entries == {
        "PORT": ("5173", 4, False),
        "API_PORT": ("8080", 5, False),
        "VITE_HOST": ("127.0.0.1", 6, False),
        "DATABASE_URL": ("postgres://app:change-me@localhost:5432/app_dev", 8, False),
        "REDIS_URL": ("redis://localhost:6379/0", 9, False),
        "CACHE_DIR": ("/tmp/app-cache", 10, False),
        "PUBLIC_URL": ("https://example.test/#anchor", 11, False),
        "EMPTY": ("", 12, False),
        "SPACED": ("  kept  ", 13, False),
        "MULTILINE_CERT": (
            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            15,
            False,
        ),
        "AFTER_MULTILINE": ("1", 18, False),
        "UPLOAD_DIR": ("${DATA_ROOT}/uploads", 20, True),
        "LITERAL": ("${NOT_EXPANDED}", 21, False),
        "ESCAPED": ('line\nnext "quoted"', 22, False),
    }


def test_the_last_definition_wins() -> None:
    assert _parse("PORT=1\nPORT=2\n")["PORT"] == ("2", 2, False)


def test_windows_line_endings() -> None:
    assert _parse("PORT=1\r\nHOST=a\r\n") == {"PORT": ("1", 1, False), "HOST": ("a", 2, False)}


@pytest.mark.parametrize(
    ("line", "reference"),
    [
        ("A=$HOME/x", True),
        ("A=${HOME}", True),
        ('A="${HOME}"', True),
        ("A='$HOME'", False),
        ("A=price$", False),
        ("A=a$1", False),
    ],
)
def test_references_are_marked_not_expanded(line: str, reference: bool) -> None:
    value, _, marked = _parse(line)["A"]
    assert "$" in value
    assert marked is reference


def test_an_unclosed_quote_does_not_swallow_the_file() -> None:
    entries = _parse('A="never closed\nB=2\n')
    assert "A" not in entries
    assert entries["B"] == ("2", 2, False)


def test_values_are_kept_out_of_repr() -> None:
    from ifinjected.parsers.dotenv import parse_dotenv

    (entry,) = parse_dotenv("DB_PASSWORD=hunter2\n")
    assert "hunter2" not in repr(entry)


@given(st.text(max_size=400))
def test_any_text_parses_without_errors(text: str) -> None:
    from ifinjected.parsers.dotenv import parse_dotenv

    line_count = len(text.splitlines()) or 1
    for entry in parse_dotenv(text):
        assert 1 <= entry.line <= line_count
        assert entry.key


def test_a_quoted_value_spans_at_most_200_lines() -> None:
    from ifinjected.parsers.dotenv import MAX_VALUE_LINES

    body = "\n".join("x" for _ in range(MAX_VALUE_LINES + 5))
    entries = _parse(f'A="{body}"\nB=2\n')
    assert "A" not in entries  # treated as never closed: a scan stays linear
    assert entries["B"][0] == "2"
    assert _parse('A="one\ntwo"\n')["A"] == ("one\ntwo", 1, False)
