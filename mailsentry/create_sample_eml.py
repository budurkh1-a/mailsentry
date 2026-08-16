"""Create a simple sample phishing .eml file for parser testing."""

from __future__ import annotations

from pathlib import Path


def create_sample_eml(output_path: str = "sample_phishing.eml") -> Path:
    """Write a dummy phishing email to disk."""
    content = """From: Alice Johnson <alice@evil.example>
To: employee@company.example
Subject: Urgent: Verify Your Password Now
Date: Fri, 24 Jul 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=\"utf-8\"

Hello,
Your account is at risk and requires immediate password verification.
Click here to restore access and avoid suspension.
https://phish.example/login
"""

    path = Path(output_path)
    path.write_text(content, encoding="utf-8")
    return path


if __name__ == "__main__":
    created = create_sample_eml()
    print(f"Created sample email at {created}")
