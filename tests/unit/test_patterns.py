"""Absolute path patterns: *, **, ?, sets, directories covering their contents."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ifinjected.policy.patterns import inside, matches


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/home/a/.ssh/**", "/home/a/.ssh/id_ed25519", True),
        ("/home/a/.ssh/**", "/home/a/.ssh/keys/deep/id", True),
        ("/home/a/.ssh", "/home/a/.ssh/id_ed25519", True),  # a directory covers its contents
        ("/home/a/.ssh", "/home/a/.ssh", True),
        ("/home/a/.ssh", "/home/a/.sshx/id", False),
        ("/home/a/.ssh/*", "/home/a/.ssh/id_rsa", True),
        ("/home/a/.ssh/*", "/home/a/.ssh/sub/id_rsa", True),  # covers the directory sub
        ("/home/a/.ssh/id_*", "/home/a/.ssh/id_rsa", True),
        ("/home/a/.ssh/id_*", "/home/a/.ssh/config", False),
        ("/home/a/**/.env", "/home/a/src/app/.env", True),
        ("/home/a/**/.env", "/home/a/.env", True),  # ** matches zero segments
        ("/home/a/**/.env", "/home/a/src/app/.env.local", False),
        ("/home/a/**/.env*", "/home/a/src/app/.env.local", True),
        ("/home/?/x", "/home/a/x", True),
        ("/home/?/x", "/home/ab/x", False),
        ("/home/[ab]/x", "/home/b/x", True),
        ("/home/[!ab]/x", "/home/b/x", False),
        ("/home/a/[x", "/home/a/[x", True),  # an unclosed set is a literal
        ("/**", "/anything/at/all", True),
        ("**", "/anything/at/all", True),
        ("**", "C:\\Users\\a\\x", True),
        ("/home/a", "/home/A", False),  # case-sensitive on POSIX
        ("C:\\Users\\a\\.ssh\\**", "c:\\users\\A\\.ssh\\id_rsa", True),  # not on Windows
        ("C:\\Users\\a\\.ssh", "D:\\Users\\a\\.ssh\\x", False),
        ("C:\\Users\\a", "/home/a", False),
        ("/home/a/.ssh", "relative/path", False),
    ],
)
def test_matches(pattern: str, path: str, expected: bool) -> None:
    assert matches(pattern, path) is expected


def test_inside_treats_wildcards_in_the_directory_literally() -> None:
    assert inside("/home/a/[weird]*", "/home/a/[weird]*/file")
    assert not inside("/home/a/[weird]*", "/home/a/w/file")
    assert inside("/srv/app", "/srv/app")
    assert not inside("/srv/app", "/srv/application")


_segment = st.text(alphabet="abcxyz.-_0123456789", min_size=1, max_size=8).filter(
    lambda s: s not in {".", ".."}
)
_paths = st.lists(_segment, min_size=1, max_size=6).map(lambda parts: "/" + "/".join(parts))


@given(path=_paths)
def test_a_path_matches_itself_and_double_star_below_its_parent(path: str) -> None:
    assert matches(path, path)
    parent = path.rsplit("/", 1)[0] or ""
    assert matches(parent + "/**", path)


@given(base=_paths, rest=st.lists(_segment, min_size=1, max_size=4))
def test_a_directory_covers_everything_below_it(base: str, rest: list[str]) -> None:
    assert matches(base, base + "/" + "/".join(rest))
    assert inside(base, base + "/" + "/".join(rest))


@given(a=_paths, b=_paths)
def test_literal_patterns_only_cover_themselves_and_descendants(a: str, b: str) -> None:
    expected = b == a or b.startswith(a + "/")
    assert inside(a, b) is expected
