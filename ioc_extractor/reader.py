"""Format-aware text extraction from different input file types."""

from __future__ import annotations

import email
import email.policy
from pathlib import Path


def read_text(path: Path) -> str:
    """Reads *path* and returns its plain-text content.

    Supports RFC 2822 email files (``.eml``) and arbitrary plain-text files.
    For ``.eml`` files the MIME structure is decoded so that base64- or
    quoted-printable-encoded body parts are readable and IOC extraction works
    on the actual message content.
    """
    if path.suffix.lower() == ".eml":
        return _read_eml(path)
    return path.read_text(encoding="utf-8")


def _read_eml(path: Path) -> str:
    """Parses an RFC 2822 ``.eml`` file and returns headers + decoded body."""
    msg = email.message_from_bytes(path.read_bytes(), policy=email.policy.compat32)
    parts: list[str] = []

    # Headers contain IOCs too (Received: IPs, From:/Reply-To: addresses, …).
    for key, value in msg.items():
        parts.append(f"{key}: {value}")

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    assert isinstance(payload, bytes)
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            assert isinstance(payload, bytes)
            charset = msg.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, errors="replace"))

    return "\n".join(parts)
