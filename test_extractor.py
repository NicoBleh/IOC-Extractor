"""Unit-Tests für die IOC-Erkennung und -Normalisierung."""

from __future__ import annotations

import pytest

from ioc_extractor import IOCExtractor
from ioc_extractor.patterns import refang


@pytest.fixture
def extractor() -> IOCExtractor:
    """Stellt eine frische Extractor-Instanz je Test bereit."""
    return IOCExtractor()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hxxps://evil[.]test/a", "https://evil.test/a"),
        ("hxxp://evil[.]test", "http://evil.test"),
        ("198.51.100[.]23", "198.51.100.23"),
        ("mail[.]example", "mail.example"),
    ],
)
def test_refang(raw: str, expected: str) -> None:
    assert refang(raw) == expected


def test_extracts_each_type(extractor: IOCExtractor) -> None:
    text = (
        "Kontakt a@b.example von 203.0.113[.]47 ueber "
        "hxxp://bad[.]example/x, Hash 44d88612fea8a8f36de82e1278abb02f, "
        "Luecke CVE-2024-3400."
    )
    types = {ioc.type for ioc in extractor.extract(text)}
    assert {"email", "ipv4", "url", "md5", "cve"} <= types


def test_deduplicates_across_forms(extractor: IOCExtractor) -> None:
    # Gleiche IP einmal entschärft, einmal normal -> ein eindeutiger Treffer.
    text = "203.0.113[.]47 und 203.0.113.47"
    ips = [ioc for ioc in extractor.extract(text) if ioc.type == "ipv4"]
    assert len(ips) == 1
    assert ips[0].value == "203.0.113.47"


def test_invalid_octet_is_rejected(extractor: IOCExtractor) -> None:
    ips = [ioc for ioc in extractor.extract("999.1.1.1") if ioc.type == "ipv4"]
    assert ips == []


def test_file_extension_is_not_a_domain(extractor: IOCExtractor) -> None:
    domains = [ioc for ioc in extractor.extract("payload.exe") if ioc.type == "domain"]
    assert domains == []


def test_sha256_not_split_into_md5(extractor: IOCExtractor) -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extractor.extract(sha256)
    assert any(ioc.type == "sha256" and ioc.value == sha256 for ioc in iocs)
    assert not any(ioc.type == "md5" for ioc in iocs)


def test_was_defanged_flag(extractor: IOCExtractor) -> None:
    (ip,) = (ioc for ioc in extractor.extract("203.0.113[.]47") if ioc.type == "ipv4")
    assert ip.was_defanged is True
    assert ip.original == "203.0.113[.]47"
