"""Kernlogik: Extraktion von Indicators of Compromise aus beliebigem Text."""

from __future__ import annotations

from collections import defaultdict

from ioc_extractor.models import IOC
from ioc_extractor.patterns import FILE_EXTENSIONS, PATTERNS, refang


class IOCExtractor:
    """Findet Indicators of Compromise in einem Text.

    Die Erkennung erfolgt rein musterbasiert über reguläre Ausdrücke.
    Gefundene Treffer werden normalisiert (Refang), grob validiert und
    über ein ``set`` automatisch dedupliziert.
    """

    def extract(self, text: str) -> set[IOC]:
        """Extrahiert alle eindeutigen IOCs aus ``text``.

        Args:
            text: Der zu durchsuchende Freitext.

        Returns:
            Eine Menge eindeutiger :class:`IOC`-Objekte.
        """
        found: set[IOC] = set()
        for ioc_type, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                original = match.group(0)
                if ioc_type == "url":
                    # Nachgestellte Satzzeichen (z. B. Punkt am Satzende)
                    # gehören nicht zur URL.
                    original = original.rstrip(".,;:)]>\"'")
                value = refang(original)
                if not self._is_valid(ioc_type, value):
                    continue
                if ioc_type == "cve":
                    value = value.upper()
                found.add(IOC(type=ioc_type, value=value, original=original))
        return found

    def extract_grouped(self, text: str) -> dict[str, list[IOC]]:
        """Wie :meth:`extract`, jedoch nach Typ gruppiert und je Gruppe sortiert."""
        grouped: dict[str, list[IOC]] = defaultdict(list)
        for ioc in self.extract(text):
            grouped[ioc.type].append(ioc)
        for items in grouped.values():
            items.sort(key=lambda ioc: ioc.value)
        return dict(grouped)

    @staticmethod
    def _is_valid(ioc_type: str, value: str) -> bool:
        """Filtert offensichtliche False Positives anhand einfacher Regeln."""
        if ioc_type == "ipv4":
            octets = value.split(".")
            return len(octets) == 4 and all(
                octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets
            )
        if ioc_type == "domain":
            tld = value.rsplit(".", 1)[-1].lower()
            return tld not in FILE_EXTENSIONS
        return True
