"""Unit tests for IOC detection, normalization, reader, and enricher."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ioc_extractor import IOCExtractor
from ioc_extractor.enricher import (
    Enricher,
    MissingApiKeyError,
    get_api_key,
    supports,
)
from ioc_extractor.patterns import refang
from ioc_extractor.reader import read_text


@pytest.fixture
def extractor() -> IOCExtractor:
    """Provides a fresh extractor instance per test."""
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
        "Contact a@b.example from 203.0.113[.]47 via "
        "hxxp://bad[.]example/x, hash 44d88612fea8a8f36de82e1278abb02f, "
        "vulnerability CVE-2024-3400."
    )
    types = {ioc.type for ioc in extractor.extract(text)}
    assert {"email", "ipv4", "url", "md5", "cve"} <= types


def test_deduplicates_across_forms(extractor: IOCExtractor) -> None:
    # Same IP once defanged, once normal -> one unique match.
    text = "203.0.113[.]47 and 203.0.113.47"
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


# ---------------------------------------------------------------------------
# reader — .eml MIME parsing
# ---------------------------------------------------------------------------


def test_read_text_plain_file(tmp_path: Path) -> None:
    """Plain text files are returned as-is."""
    f = tmp_path / "report.txt"
    f.write_text("203.0.113.1 is suspicious", encoding="utf-8")
    assert "203.0.113.1" in read_text(f)


def test_read_eml_decodes_body(tmp_path: Path) -> None:
    """IOCs in a plain-text .eml body are accessible after parsing."""
    raw = textwrap.dedent("""\
        From: attacker@evil.example
        To: victim@corp.example
        Subject: Test
        Content-Type: text/plain; charset="utf-8"

        Visit hxxps://malware[.]example/payload and run it.
        Hash: 44d88612fea8a8f36de82e1278abb02f
    """)
    eml = tmp_path / "sample.eml"
    eml.write_bytes(raw.encode())
    text = read_text(eml)
    assert "malware" in text
    assert "44d88612fea8a8f36de82e1278abb02f" in text


def test_read_eml_includes_headers(tmp_path: Path) -> None:
    """Header fields (Received: IPs, From: addresses) are included in output."""
    raw = textwrap.dedent("""\
        From: sender@198.51.100.5
        Received: from mail.example (198.51.100.99)
        Subject: Hi

        Body text.
    """)
    eml = tmp_path / "headers.eml"
    eml.write_bytes(raw.encode())
    text = read_text(eml)
    assert "198.51.100.99" in text


def test_read_eml_base64_body(tmp_path: Path) -> None:
    """Base64-encoded body parts are decoded before extraction."""
    import base64

    body_b64 = base64.b64encode(b"Contact evil@malware.example for ransom.\n").decode()
    raw = (
        "From: x@x.example\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "Content-Transfer-Encoding: base64\n"
        "\n"
        f"{body_b64}\n"
    )
    eml = tmp_path / "encoded.eml"
    eml.write_bytes(raw.encode())
    text = read_text(eml)
    assert "evil@malware.example" in text


# ---------------------------------------------------------------------------
# enricher — reputation API (mocked)
# ---------------------------------------------------------------------------


def test_supports() -> None:
    assert supports("ipv4") is True
    assert supports("domain") is False
    assert supports("sha256") is False


def test_get_api_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError, match="ABUSEIPDB_API_KEY"):
        get_api_key()


def test_get_api_key_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey123")
    assert get_api_key() == "testkey123"


def test_enrich_malicious() -> None:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 95}}
    mock_resp.raise_for_status.return_value = None

    with (
        patch("requests.get", return_value=mock_resp),
        patch("ioc_extractor.enricher.time.sleep"),
    ):
        rep = Enricher("fakekey").enrich("198.51.100.1", "ipv4")

    assert rep is not None
    assert rep.verdict == "malicious"
    assert rep.score == 95


def test_enrich_clean() -> None:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 0}}
    mock_resp.raise_for_status.return_value = None

    with (
        patch("requests.get", return_value=mock_resp),
        patch("ioc_extractor.enricher.time.sleep"),
    ):
        rep = Enricher("fakekey").enrich("203.0.113.1", "ipv4")

    assert rep is not None
    assert rep.verdict == "clean"


def test_enrich_unsupported_type() -> None:
    assert Enricher("fakekey").enrich("evil.example", "domain") is None
