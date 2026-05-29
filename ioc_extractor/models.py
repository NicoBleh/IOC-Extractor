"""Datenmodell für extrahierte Indicators of Compromise (IOCs)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IOC:
    """Ein einzelner Indicator of Compromise.

    Attributes:
        type: Kategorie des Indikators (z. B. ``"ipv4"`` oder ``"domain"``).
        value: Normalisierter (refangter) Wert des Indikators.
        original: Ursprüngliche Schreibweise im Quelltext. Dieses Feld wird
            beim Vergleich und beim Hashing absichtlich ignoriert
            (``compare=False``), damit zwei Vorkommen desselben Indikators –
            unabhängig von einer evtl. „entschärften" Schreibweise – als
            identisch gelten und über ein ``set`` automatisch dedupliziert
            werden.
    """

    type: str
    value: str
    original: str = field(default="", compare=False)

    @property
    def was_defanged(self) -> bool:
        """Gibt an, ob der Indikator im Quelltext entschärft dargestellt war."""
        return bool(self.original) and self.original != self.value
