"""Kommandozeilen-Schnittstelle für den IOC-Extractor."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from ioc_extractor.extractor import IOCExtractor
from ioc_extractor.models import IOC

#: Anzeige-Reihenfolge und -Bezeichnungen der IOC-Typen.
TYPE_LABELS: dict[str, str] = {
    "ipv4": "IPv4-Adressen",
    "domain": "Domains",
    "url": "URLs",
    "email": "E-Mail-Adressen",
    "md5": "Hashes (MD5)",
    "sha1": "Hashes (SHA1)",
    "sha256": "Hashes (SHA256)",
    "cve": "CVEs",
}


def build_parser() -> argparse.ArgumentParser:
    """Erstellt den Argument-Parser der Kommandozeile."""
    parser = argparse.ArgumentParser(
        prog="ioc-extractor",
        description="Extrahiert Indicators of Compromise aus einer Textdatei.",
    )
    parser.add_argument("input", type=Path, help="Pfad zur Eingabe-Textdatei")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Pfad für den CSV-Export (Standard: <input>_iocs.csv)",
    )
    return parser


def print_report(grouped: dict[str, list[IOC]]) -> int:
    """Gibt die gefundenen IOCs gruppiert auf der Konsole aus.

    Returns:
        Die Gesamtzahl der eindeutigen IOCs.
    """
    total = 0
    print("=" * 60)
    print("  EXTRAHIERTE INDICATORS OF COMPROMISE")
    print("=" * 60)
    for ioc_type, label in TYPE_LABELS.items():
        items = grouped.get(ioc_type, [])
        if not items:
            continue
        total += len(items)
        print(f"\n{label} ({len(items)})")
        for ioc in items:
            note = f"   (refanged aus {ioc.original})" if ioc.was_defanged else ""
            print(f"  {ioc.value}{note}")
    print("\n" + "-" * 60)
    print(f"  {total} eindeutige IOCs gefunden")
    print("=" * 60)
    return total


def write_csv(grouped: dict[str, list[IOC]], path: Path) -> None:
    """Schreibt die gefundenen IOCs als CSV-Datei."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "value", "refanged_from"])
        for ioc_type in TYPE_LABELS:
            for ioc in grouped.get(ioc_type, []):
                refanged_from = ioc.original if ioc.was_defanged else ""
                writer.writerow([ioc.type, ioc.value, refanged_from])


def main(argv: list[str] | None = None) -> int:
    """Einstiegspunkt der Kommandozeile."""
    args = build_parser().parse_args(argv)

    try:
        text = args.input.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Fehler beim Lesen der Datei: {exc}", file=sys.stderr)
        return 1

    grouped = IOCExtractor().extract_grouped(text)
    print_report(grouped)

    output = args.output or args.input.with_name(f"{args.input.stem}_iocs.csv")
    write_csv(grouped, output)
    print(f"\nExport gespeichert: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
