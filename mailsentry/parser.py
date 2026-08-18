"""Email parsing utilities for MailSentry.

The parser uses Python's standard library email package to load and inspect raw RFC 822
messages from .eml files or raw text. It returns a clean dataclass that contains the
message headers, body text, extracted links, and attachment metadata.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Tuple


class ParseError(Exception):
    """Raised when an email cannot be loaded or parsed."""


@dataclass
class ParsedEmail:
    """Structured representation of an email message."""

    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    html_text: str = ""
    html_body: str = ""
    links: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "headers": self.headers,
            "body_text": self.body_text,
            "html_text": self.html_text,
            "html_body": self.html_body,
            "links": self.links,
            "attachments": self.attachments,
        }


def load_email_source(source: Any) -> Tuple[bytes, str]:
    """Load raw bytes from a file path, bytes payload, or raw RFC 822 text."""
    if isinstance(source, bytes):
        return source, "raw-bytes"

    if isinstance(source, str):
        if os.path.exists(source):
            path = Path(source)
            if not path.is_file():
                raise ParseError(f"Path is not a file: {source}")
            return path.read_bytes(), str(path)

        if "From:" in source or "To:" in source or "Subject:" in source:
            return source.encode("utf-8", errors="replace"), "raw-text"

        raise ParseError("Input string does not look like a file path or email content")

    raise ParseError("Unsupported email source type")


def parse_email(source: Any) -> ParsedEmail:
    """Parse raw RFC 822 content into a ParsedEmail dataclass."""
    raw_bytes, _ = load_email_source(source)
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    headers = {key: value for key, value in message.items()}
    plain_parts: List[str] = []
    html_parts: List[str] = []
    raw_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()

        if disposition == "attachment":
            payload = part.get_payload(decode=True)
            attachments.append(
                {
                    "filename": part.get_filename() or "unnamed",
                    "content_type": content_type,
                    "size_bytes": len(payload or b""),
                }
            )
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")

        if content_type == "text/plain":
            plain_parts.append(text)
        elif content_type == "text/html":
            raw_html_parts.append(text)
            html_parts.append(re.sub(r"<[^>]+>", " ", text))

    plain_text = "\n".join(plain_parts).strip()
    html_text = "\n".join(html_parts).strip()
    html_body = "\n".join(raw_html_parts).strip()
    if not plain_text and html_text:
        plain_text = html_text

    body_text = "\n".join([plain_text, html_text]).strip()
    links = re.findall(r"https?://[^\s)>'\"]+", body_text)

    return ParsedEmail(
        headers=headers,
        body_text=body_text,
        html_text=html_text,
        html_body=html_body,
        links=links,
        attachments=attachments,
    )
