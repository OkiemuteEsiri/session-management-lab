from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import assess
from .models import SessionPolicy
from .reporting import render_markdown


def load_policies(path: Path) -> list[SessionPolicy]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    return [SessionPolicy(**item) for item in raw]


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic session-management policies")
    parser.add_argument("input", type=Path, help="Path to JSON policy inventory")
    parser.add_argument("--output", type=Path, help="Optional Markdown report path")
    args = parser.parse_args()

    findings = []
    for policy in load_policies(args.input):
        findings.extend(assess(policy))

    report = render_markdown(findings)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
