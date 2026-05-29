"""Data model for extracted Indicators of Compromise (IOCs)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IOC:
    """A single Indicator of Compromise.

    Attributes:
        type: Category of the indicator (e.g. ``"ipv4"`` or ``"domain"``).
        value: Normalized (refanged) value of the indicator.
        original: Original representation in the source text. This field is
            intentionally excluded from comparison and hashing
            (``compare=False``), so that two occurrences of the same indicator —
            regardless of any defanged representation — are considered
            identical and automatically deduplicated via a ``set``.
    """

    type: str
    value: str
    original: str = field(default="", compare=False)

    @property
    def was_defanged(self) -> bool:
        """Returns whether the indicator was defanged in the source text."""
        return bool(self.original) and self.original != self.value
