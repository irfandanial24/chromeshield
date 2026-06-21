"""
cli.py
------
Command-line interface for ExtenShield.

Usage:
    python cli.py path/to/extension_folder
    python cli.py path/to/extension.zip
    python cli.py path/to/extension.crx --json

Examples:
    python cli.py samples/malicious_extension
    python cli.py samples/benign_extension --json
"""

import argparse
import json
import sys

from extenshield import scan
from extenshield.report import format_text


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="ExtenShield - detect malicious Chrome extensions (static analysis)."
    )
    parser.add_argument("path", help="Extension folder, .zip, or .crx file to scan.")
    parser.add_argument("--json", action="store_true",
                        help="Output the report as JSON instead of text.")
    args = parser.parse_args(argv)

    try:
        report = scan(args.path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text(report))

    # Exit code reflects risk so the tool can be used in scripts/CI:
    # 0 = minimal/low, 1 = medium/high.
    return 0 if report.level in ("MINIMAL", "LOW") else 1


if __name__ == "__main__":
    raise SystemExit(main())
