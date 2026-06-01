"""Reputation enrichment for IOCs via AbuseIPDB.

API key must be provided via the ``ABUSEIPDB_API_KEY`` environment variable
(or a ``.env`` file in the working directory).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

#: IOC types supported by AbuseIPDB.
SUPPORTED_TYPES: frozenset[str] = frozenset({"ipv4"})

#: Seconds to wait between requests.
_RATE_DELAY: float = 0.5

ENV_KEY = "ABUSEIPDB_API_KEY"


class MissingApiKeyError(RuntimeError):
    """Raised when the AbuseIPDB API key is not configured."""


@dataclass
class Reputation:
    """Reputation result for a single IOC from AbuseIPDB.

    Attributes:
        score:   Abuse confidence score 0-100.
        verdict: One of ``"clean"``, ``"suspicious"``, or ``"malicious"``.
    """

    score: int
    verdict: str


def get_api_key() -> str:
    """Returns the AbuseIPDB API key from the environment.

    Raises:
        OSError: If ``ABUSEIPDB_API_KEY`` is not set.
    """
    key = os.environ.get(ENV_KEY, "").strip()
    if not key:
        raise MissingApiKeyError(
            f"AbuseIPDB API key not found. Set the {ENV_KEY} environment variable."
        )
    return key


def supports(ioc_type: str) -> bool:
    """Returns whether AbuseIPDB can enrich IOCs of *ioc_type*."""
    return ioc_type in SUPPORTED_TYPES


class Enricher:
    """Enriches IPv4 IOCs with AbuseIPDB reputation data.

    Args:
        api_key: AbuseIPDB API key.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def enrich(self, ioc_value: str, ioc_type: str) -> Reputation | None:
        """Queries AbuseIPDB for *ioc_value*.

        Returns ``None`` for IOC types other than ``ipv4``.
        Sleeps briefly after each request to respect the API rate limit.
        """
        if not supports(ioc_type):
            return None
        import requests  # optional dependency; imported lazily

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": ioc_value, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        score: int = resp.json()["data"]["abuseConfidenceScore"]
        time.sleep(_RATE_DELAY)
        return Reputation(score=score, verdict=_score_to_verdict(score))


def _score_to_verdict(score: int) -> str:
    if score >= 80:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"
