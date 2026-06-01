"""Command-line interface for the IOC extractor."""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ioc_extractor.enricher import Reputation

from ioc_extractor.extractor import IOCExtractor
from ioc_extractor.models import IOC
from ioc_extractor.reader import read_text


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Loads key=value pairs from *path* into the environment.

    Already-set variables are not overwritten, so explicit ``export`` always
    takes precedence. Lines starting with ``#`` and blank lines are ignored.
    """
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'")
        os.environ.setdefault(key, value)


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
    parser.add_argument(
        "input",
        type=Path,
        help="Path to the input file (.txt, .log, .eml, …)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Path for the CSV export (default: <input>_iocs.csv)",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        default=False,
        help="Enrich IPv4 IOCs with AbuseIPDB reputation data (requires ABUSEIPDB_API_KEY).",
    )
    return parser


def print_report(
    grouped: dict[str, list[IOC]],
    enrichment: dict[tuple[str, str], Reputation] | None = None,
) -> int:
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
            rep_note = ""
            if enrichment and (ioc.type, ioc.value) in enrichment:
                rep = enrichment[(ioc.type, ioc.value)]
                rep_note = f"   [AbuseIPDB: {rep.verdict.upper()} {rep.score}%]"
            print(f"  {ioc.value}{note}{rep_note}")
    print("\n" + "-" * 60)
    print(f"  {total} unique IOCs found")
    print("=" * 60)
    return total


def write_csv(
    grouped: dict[str, list[IOC]],
    path: Path,
    enrichment: dict[tuple[str, str], Reputation] | None = None,
) -> None:
    """Writes the found IOCs to a CSV file."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        headers = ["type", "value", "refanged_from"]
        if enrichment is not None:
            headers += ["abuseipdb_verdict", "abuseipdb_score"]
        writer.writerow(headers)
        for ioc_type in TYPE_LABELS:
            for ioc in grouped.get(ioc_type, []):
                row = [
                    ioc.type,
                    ioc.value,
                    ioc.original if ioc.was_defanged else "",
                ]
                if enrichment is not None:
                    rep = enrichment.get((ioc.type, ioc.value))
                    if rep:
                        row += [rep.verdict, rep.score]
                    else:
                        row += ["", ""]
                writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the command-line interface."""
    _load_dotenv()
    args = build_parser().parse_args(argv)

    try:
        text = read_text(args.input)
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 1

    grouped = IOCExtractor().extract_grouped(text)

    enrichment: dict[tuple[str, str], Reputation] | None = None
    if args.enrich:
        from ioc_extractor.enricher import Enricher, get_api_key, supports

        try:
            api_key = get_api_key()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        enricher = Enricher(api_key)
        enrichment = {}
        all_iocs = [ioc for items in grouped.values() for ioc in items]
        enrichable = [ioc for ioc in all_iocs if supports(ioc.type)]
        print(f"Enriching {len(enrichable)} IPv4 IOCs via AbuseIPDB…")
        for ioc in enrichable:
            try:
                rep = enricher.enrich(ioc.value, ioc.type)
                if rep:
                    enrichment[(ioc.type, ioc.value)] = rep
            except Exception as exc:  # noqa: BLE001
                print(
                    f"  Warning: enrichment failed for {ioc.value}: {exc}",
                    file=sys.stderr,
                )

    print_report(grouped, enrichment)

    output = args.output or args.input.with_name(f"{args.input.stem}_iocs.csv")
    write_csv(grouped, output, enrichment)
    print(f"\nExport saved: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
