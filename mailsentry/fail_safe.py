"""Shared fail-safe responses for incomplete email analysis."""

from __future__ import annotations

from typing import Any, Dict, Optional


UNVERIFIED_DETAILS = "A required email security check failed due to a system error. Manual review is required."


def system_error_details(check: str, error: Exception | str) -> str:
    """Return an operator-facing explanation without exposing a traceback."""
    return f"{UNVERIFIED_DETAILS} Failed check: {check}. Error: {error}"


def unverified_result(
    check: str,
    error: Exception | str,
    *,
    subject: str = "",
    from_address: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the mandatory neutral decision used when analysis is incomplete."""
    details = system_error_details(check, error)
    result: Dict[str, Any] = {
        "verdict": "UNVERIFIED",
        "status": "WARNING",
        "score": 50,
        "decision": "WARNING",
        "action": "MANUAL_REVIEW",
        "risk_score": 50,
        "risk_level": "medium",
        "severity": "medium",
        "reason": details,
        "details": details,
        "indicators": ["System error during email analysis"],
        "policy_hits": [],
        "threat_narrative": details,
        "subject": subject,
        "from_address": from_address,
        "analysis_error": {"check": check, "message": str(error)},
    }
    if extra:
        result.update(extra)
    return result


def unverified_check_result(check: str, error: Exception | str) -> Dict[str, Any]:
    """Mark an individual check as unavailable so callers cannot treat it as a failure."""
    return {
        "error": True,
        "check": check,
        "details": system_error_details(check, error),
    }
