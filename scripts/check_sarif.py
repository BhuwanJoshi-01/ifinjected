"""Validate a SARIF file against the official SARIF 2.1.0 JSON schema.

    uv run python scripts/check_sarif.py SCHEMA.json REPORT.sarif

CI downloads the schema from the OASIS repository at a pinned commit and checks its
sha256 first; it is not vendored here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft4Validator


def main(schema_path: str, report_path: str) -> int:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    errors = sorted(Draft4Validator(schema).iter_errors(report), key=lambda e: list(e.path))
    for error in errors:
        print(f"{'/'.join(map(str, error.absolute_path))}: {error.message}", file=sys.stderr)
    results = len(report["runs"][0]["results"])
    print(f"{report_path}: {len(errors)} schema errors, {results} results")
    return 1 if errors or not results else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
