"""Core logic: extraction of Indicators of Compromise from arbitrary text."""

from __future__ import annotations

from collections import defaultdict

from ioc_extractor.models import IOC
from ioc_extractor.patterns import FILE_EXTENSIONS, PATTERNS, refang


class IOCExtractor:
    """Finds Indicators of Compromise in a text.

    Detection is purely pattern-based using regular expressions.
    Matches are normalized (refanged), coarsely validated, and
    automatically deduplicated via a ``set``.
    """

    def extract(self, text: str) -> set[IOC]:
        """Extracts all unique IOCs from ``text``.

        Args:
            text: The free-form text to search.

        Returns:
            A set of unique :class:`IOC` objects.
        """
        found: set[IOC] = set()
        for ioc_type, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                original = match.group(0)
                if ioc_type == "url":
                    # Trailing punctuation (e.g. period at end of sentence)
                    # is not part of the URL.
                    original = original.rstrip(".,;:)]>\"'")
                value = refang(original)
                if not self._is_valid(ioc_type, value):
                    continue
                if ioc_type == "cve":
                    value = value.upper()
                found.add(IOC(type=ioc_type, value=value, original=original))
        return found

    def extract_grouped(self, text: str) -> dict[str, list[IOC]]:
        """Like :meth:`extract`, but grouped by type and sorted within each group."""
        grouped: dict[str, list[IOC]] = defaultdict(list)
        for ioc in self.extract(text):
            grouped[ioc.type].append(ioc)
        for items in grouped.values():
            items.sort(key=lambda ioc: ioc.value)
        return dict(grouped)

    @staticmethod
    def _is_valid(ioc_type: str, value: str) -> bool:
        """Filters obvious false positives using simple rules."""
        if ioc_type == "ipv4":
            octets = value.split(".")
            return len(octets) == 4 and all(
                octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets
            )
        if ioc_type == "domain":
            tld = value.rsplit(".", 1)[-1].lower()
            return tld not in FILE_EXTENSIONS
        return True
