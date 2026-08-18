"""Detection of sender domains impersonating high-value brands."""

from __future__ import annotations

from difflib import SequenceMatcher
from email.utils import getaddresses
from typing import Any, Dict, List, Sequence


HIGH_VALUE_TARGET_DOMAINS: List[str] = [
    "amazon.com",
    "microsoft.com",
    "google.com",
    "paypal.com",
]
SIMILARITY_THRESHOLD = 0.80


def extract_sender_domain(from_header: str) -> str:
    """Extract and normalize the first email domain in a From header."""
    addresses = getaddresses([from_header or ""])
    address = addresses[0][1] if addresses else ""
    return address.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in address else ""


def detect_typosquatting(
    from_header: str,
    *,
    target_domains: Sequence[str] = HIGH_VALUE_TARGET_DOMAINS,
) -> Dict[str, Any]:
    """Flag non-exact sender domains that closely resemble a protected brand."""
    sender_domain = extract_sender_domain(from_header)
    best_target = ""
    best_similarity = 0.0

    for target in target_domains:
        normalized_target = target.lower().rstrip(".")
        if sender_domain == normalized_target:
            return {
                "sender_domain": sender_domain,
                "target_domain": normalized_target,
                "similarity": 1.0,
                "status": "CLEAN",
                "is_suspicious": False,
            }
        similarity = SequenceMatcher(None, sender_domain, normalized_target).ratio()
        if similarity > best_similarity:
            best_target, best_similarity = normalized_target, similarity

    suspicious = bool(sender_domain and best_similarity > SIMILARITY_THRESHOLD)
    return {
        "sender_domain": sender_domain,
        "target_domain": best_target,
        "similarity": round(best_similarity, 3),
        "status": "SUSPICIOUS_TYPOSQUATTING" if suspicious else "CLEAN",
        "is_suspicious": suspicious,
    }
