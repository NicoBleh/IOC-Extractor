"""Reguläre Ausdrücke und Normalisierung für die IOC-Erkennung."""

from __future__ import annotations

import re

# Wiederverwendbares Teilmuster: ein Punkt – normal oder „entschärft" als [.]
_DOT = r"(?:\[\.\]|\.)"

#: Bekannte Datei-Endungen, die fälschlich wie Domains aussehen können.
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {"exe", "bin", "dll", "doc", "docx", "pdf", "txt", "zip", "rar", "ps1", "js"}
)

#: Kompilierte Muster je IOC-Typ.
#: Wichtig: Die Hash-Muster sind über ``\b`` längengenau, sodass sich ein
#: SHA256-Wert nicht versehentlich als MD5-Teilstring matchen lässt.
PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\b(?:hxxps?|https?)(?:\[://\]|://)[^\s'\"<>]+", re.IGNORECASE),
    "email": re.compile(
        rf"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+{_DOT})+[a-zA-Z]{{2,}}\b"
    ),
    "ipv4": re.compile(rf"\b(?:\d{{1,3}}{_DOT}){{3}}\d{{1,3}}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(rf"\b(?:[a-zA-Z0-9-]+{_DOT})+[a-zA-Z]{{2,}}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}


def refang(text: str) -> str:
    """Wandelt eine „entschärfte" Schreibweise in die normale Form zurück.

    Beispiele:
        ``hxxps://`` -> ``https://`` und ``domain[.]com`` -> ``domain.com``.
    """
    return (
        text.replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[://]", "://")
        .replace("[.]", ".")
        .replace("[:]", ":")
    )
