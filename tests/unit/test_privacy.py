import pytest

from ifinjected.privacy import strip_control


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("plain text", "plain text"),
        ("tab\tand\nnewline", "tab\tand\nnewline"),
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b[2J\x1b[Hcleared", "cleared"),
        ("\x1b]0;evil title\x07after", "after"),
        ("\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\", "link"),
        ("bell\x07 and nul\x00", "bell and nul"),
        ("carriage\rreturn", "carriagereturn"),
        ("c1 \x9b31m", "c1 31m"),
        ("café ✓", "café ✓"),
    ],
)
def test_strip_control(raw: str, clean: str) -> None:
    assert strip_control(raw) == clean
