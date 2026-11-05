"""JSON with comments and trailing commas (as VS Code and dev containers allow) made
plain JSON, without moving any line.

Comments become spaces (their newlines are kept), and a comma that is followed only by
whitespace and a closing bracket is dropped. Strings are left exactly as they are, so
``"a // b"`` stays a string.
"""

from __future__ import annotations

import re

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def strip_jsonc(text: str) -> str:
    out: list[str] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            out.append(text[index : end + 1])
            index = end + 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.append(" " * (end - index))
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in text[index:end]))
            index = end
        else:
            out.append(char)
            index += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """Drop commas before a closing bracket, outside strings."""
    parts = re.split(r'("(?:[^"\\]|\\.)*")', text)  # odd parts are strings
    return "".join(
        part if index % 2 else _TRAILING_COMMA.sub(r" \1", part) for index, part in enumerate(parts)
    )
