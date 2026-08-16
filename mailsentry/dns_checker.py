"""DNS-based sender authentication and spoofing checks for MailSentry.

The module inspects the sender domain for SPF and DMARC DNS records and also evaluates
whether the display name appears to impersonate an internal identity while the actual
From address belongs to an external domain.
"""

from __future__ import annotations

import re
from email.utils import getaddresses
from typing import Any, Dict, List, Optional, Tuple

try:
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dns = None  # type: ignore


def normalize_name(value: str) -> str:
    """Lowercase and collapse whitespace for comparison."""
    return re.sub(r"\s+", " ", value).strip().lower()


def extract_domain(value: str) -> str:
    """Extract the domain part from an address or return-path value."""
    if not value:
        return ""
    candidate = value.strip().replace("<", "").replace(">", "")
    if "@" in candidate:
        candidate = candidate.split("@", 1)[1]
    return candidate.split("[", 1)[0].strip().lower()


def parse_from_header(from_header: str) -> Tuple[str, str]:
    """Parse the From header into a display name and email address."""
    if not from_header:
        return "", ""
    parsed = getaddresses([from_header])
    if not parsed:
        return "", ""
    display_name, address = parsed[0]
    return display_name, address


def query_txt(domain: str) -> List[str]:
    """Query TXT records for a domain when dnspython is available."""
    if not domain or dns is None:
        return []

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [answer.to_text() for answer in answers]
    except Exception:
        return []


def check_spf(domain: str) -> bool:
    """Perform a simple SPF check based on TXT records."""
    if not domain:
        return False

    records = query_txt(domain)
    spf_records = [record for record in records if record.startswith('"v=spf1') or record.startswith("v=spf1")]
    return bool(spf_records)


def check_dmarc(domain: str) -> bool:
    """Perform a simple DMARC check based on TXT records."""
    if not domain:
        return False

    records = query_txt(f"_dmarc.{domain}")
    dmarc_records = [record for record in records if record.startswith('"v=DMARC1') or record.startswith("v=DMARC1")]
    return bool(dmarc_records)


def check_display_name_spoofing(
    from_header: str,
    internal_names: Optional[List[str]] = None,
    internal_titles: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
) -> bool:
    """Flag display-name spoofing when an internal-looking identity uses an external From address."""
    display_name, from_address = parse_from_header(from_header)
    from_domain = extract_domain(from_address)

    internal_names = internal_names or []
    internal_titles = internal_titles or []
    internal_domains = internal_domains or []

    if not display_name or not from_domain:
        return False

    if from_domain in internal_domains:
        return False

    normalized_display = normalize_name(display_name)
    for name in internal_names:
        if normalize_name(name) in normalized_display:
            return True

    for title in internal_titles:
        if normalize_name(title) in normalized_display:
            return True

    return False


def evaluate_sender_authentication(
    from_header: str,
    *,
    internal_names: Optional[List[str]] = None,
    internal_titles: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Return SPF, DMARC, and display-name spoofing results in the requested dictionary shape."""
    display_name, from_address = parse_from_header(from_header)
    sender_domain = extract_domain(from_address)
    internal_domains = internal_domains or []

    is_internal_domain = sender_domain in internal_domains
    spf_pass = check_spf(sender_domain) or is_internal_domain
    dmarc_pass = check_dmarc(sender_domain) or is_internal_domain
    is_display_name_spoofed = check_display_name_spoofing(
        from_header,
        internal_names=internal_names,
        internal_titles=internal_titles,
        internal_domains=internal_domains,
    )

    details: List[str] = []
    if is_internal_domain:
        details.append("Internal domain trusted")
    if not spf_pass:
        details.append("SPF record not found")
    if not dmarc_pass:
        details.append("DMARC record not found")
    if is_display_name_spoofed:
        details.append("Display name appears to impersonate an internal identity")

    if not details:
        details.append("Sender authentication looks normal")

    return {
        "spf_pass": spf_pass,
        "dmarc_pass": dmarc_pass,
        "is_display_name_spoofed": is_display_name_spoofed,
        "details": "; ".join(details),
    }
