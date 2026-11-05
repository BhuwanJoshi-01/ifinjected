"""Configuration files with the line each setting came from."""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ifinjected.parsers.jsonc import strip_jsonc
from ifinjected.parsers.positions import ConfigSyntaxError, key_name, parse_json, parse_toml

CLAUDE_SETTINGS = """{
  "permissions": {
    "allow": ["Bash(npm run test:*)"],
    "deny": [
      "Read(./.env)",
      "Read(~/.ssh/**)"
    ]
  },
  "sandbox": {"enabled": true}
}
"""


def test_json_lines_of_keys_and_array_items() -> None:
    doc = parse_json(CLAUDE_SETTINGS)
    assert doc.data["permissions"]["deny"][1] == "Read(~/.ssh/**)"
    assert doc.line("permissions") == 2
    assert doc.line("permissions", "allow", 0) == 3
    assert doc.line("permissions", "deny") == 4
    assert doc.line("permissions", "deny", 0) == 5
    assert doc.line("permissions", "deny", 1) == 6
    assert doc.line("sandbox", "enabled") == 9


def test_a_missing_path_falls_back_to_its_closest_ancestor() -> None:
    doc = parse_json(CLAUDE_SETTINGS)
    assert doc.line("sandbox", "network", "allowedDomains") == 9
    assert doc.line("nothing") is None


def test_jsonc_comments_and_trailing_commas_keep_their_lines() -> None:
    text = (
        '{\n  // where MCP servers live\n  "mcp": {\n    "github": {"type": "remote",},\n  },\n}\n'
    )
    doc = parse_json(text, comments=True)
    assert doc.data == {"mcp": {"github": {"type": "remote"}}}
    assert doc.line("mcp", "github") == 4


def test_strings_with_escapes_and_comment_markers_are_strings() -> None:
    doc = parse_json('{"a\\"b": "x // y", "c": [1, {"d": null}]}', comments=True)
    assert doc.data == {'a"b': "x // y", "c": [1, {"d": None}]}
    assert doc.line("c", 1, "d") == 1


def test_invalid_json_says_where() -> None:
    with pytest.raises(ConfigSyntaxError, match="line 2"):
        parse_json('{\n  "a": ,\n}')


def test_key_names_for_reports() -> None:
    assert key_name(("permissions", "deny", 2)) == "permissions.deny[2]"
    assert key_name((0, "x")) == "[0].x"


CODEX_CONFIG = '''model = "gpt-5.5"
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = true
writable_roots = [
  "/tmp/cache",
]

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "x" }

[mcp_servers."docs.site"]
url = "https://example.org/mcp"
note = """
multi = "line"
"""
after = 1

[[profiles.list]]
name = "a"

[[profiles.list]]
name = "b"
'''


def test_toml_lines_of_tables_keys_and_arrays_of_tables() -> None:
    doc = parse_toml(CODEX_CONFIG)
    assert doc.data["sandbox_workspace_write"]["network_access"] is True
    assert doc.line("sandbox_mode") == 2
    assert doc.line("sandbox_workspace_write") == 4
    assert doc.line("sandbox_workspace_write", "network_access") == 5
    assert doc.line("sandbox_workspace_write", "writable_roots") == 6
    assert doc.line("mcp_servers", "github", "command") == 11
    assert doc.line("mcp_servers", "github", "env") == 13
    assert doc.line("mcp_servers", "docs.site", "url") == 16
    assert doc.line("mcp_servers", "docs.site", "after") == 20  # not fooled by the string
    assert doc.line("profiles", "list", 1, "name") == 26


def test_dotted_keys() -> None:
    doc = parse_toml('[a]\nb.c = 1\n"d.e".f = 2\n')
    assert doc.line("a", "b", "c") == 2
    assert doc.line("a", "d.e", "f") == 3


def test_invalid_toml_is_an_error() -> None:
    with pytest.raises(ConfigSyntaxError, match="not valid TOML"):
        parse_toml("a = \n")


_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=6), children, max_size=3)
    ),
    max_leaves=12,
)


@given(value=_json_values, indent=st.sampled_from([None, 2]))
def test_any_json_parses_to_the_same_values_and_its_top_keys_have_lines(
    value: object, indent: int | None
) -> None:
    text = json.dumps(value, indent=indent)
    doc = parse_json(text)
    assert doc.data == value
    if isinstance(value, dict):
        for key in value:
            assert doc.line(key) is not None


@given(value=_json_values)
def test_strip_jsonc_leaves_plain_json_alone(value: object) -> None:
    text = json.dumps(value, indent=2)
    assert json.loads(strip_jsonc(text)) == value
