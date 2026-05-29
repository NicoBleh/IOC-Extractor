"""Command-line interface for the IOC extractor."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from ioc_extractor.extractor import IOCExtractor
from ioc_extractor.models import IOC

#: Display order and labels for IOC types.
TYPE_LABELS: dict[str, str] = {
    "ipv4": "IPv4 Addresses",
    "domain": "Domains",
    "url": "URLs",
    "email": "Email Addresses",
    "md5": "Hashes (MD5)",
    "sha1": "Hashes (SHA1)",
    "sha256": "Hashes (SHA256)",
    "cve": "CVEs",
}


def build_parser() -> argparse.ArgumentParser:
    """Creates the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="ioc-extractor",
        description="Extracts Indicators of Compromise from a text file.",
    )
    parser.add_argument("input", type=Path, help="Path to the input text file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Path for the CSV export (default: <input>_iocs.csv)",
    )
    return parser


def print_report(grouped: dict[str, list[IOC]]) -> int:
    """Prints the found IOCs grouped to the console.

    Returns:
        The total number of unique IOCs.
    """
    total = 0
    print("=" * 60)
    print("  EXTRACTED INDICATORS OF COMPROMISE")
    print("=" * 60)
    for ioc_type, label in TYPE_LABELS.items():
        items = grouped.get(ioc_type, [])
        if not items:
            continue
        total += len(items)
        print(f"\n{label} ({len(items)})")
        for ioc in items:
            note = f"   (refanged from {ioc.original})" if ioc.was_defanged else ""
            print(f"  {ioc.value}{note}")
    print("\n" + "-" * 60)
    print(f"  {total} unique IOCs found")
    print("=" * 60)
    return total


def write_csv(grouped: dict[str, list[IOC]], path: Path) -> None:
    """Writes the found IOCs to a CSV file."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "value", "refanged_from"])
        for ioc_type in TYPE_LABELS:
            for ioc in grouped.get(ioc_type, []):
                refanged_from = ioc.original if ioc.was_defanged else ""
                writer.writerow([ioc.type, ioc.value, refanged_from])


def main(argv: list[str] | None = None) -> int:
    """Entry point for the command-line interface."""
    args = build_parser().parse_args(argv)

    try:
        text = args.input.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 1

    grouped = IOCExtractor().extract_grouped(text)
    print_report(grouped)

    output = args.output or args.input.with_name(f"{args.input.stem}_iocs.csv")
    write_csv(grouped, output)
    print(f"\nExport saved: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
