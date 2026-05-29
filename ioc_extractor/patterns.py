"""Regular expressions and normalization for IOC detection."""

from __future__ import annotations

import re

# Reusable sub-pattern: a dot — literal or defanged as [.]
_DOT = r"(?:\[\.\]|\.)"

#: Known file extensions that can be mistaken for domains.
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {"exe", "bin", "dll", "doc", "docx", "pdf", "txt", "zip", "rar", "ps1", "js"}
)

#: Compiled patterns per IOC type.
#: Important: hash patterns use ``\b`` for exact length matching so that a
#: SHA256 value is not accidentally matched as an MD5 substring.
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
    """Converts a defanged representation back to its normal form.

    Examples:
        ``hxxps://`` -> ``https://`` and ``domain[.]com`` -> ``domain.com``.
    """
    return (
        text.replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[://]", "://")
        .replace("[.]", ".")
        .replace("[:]", ":")
    )
