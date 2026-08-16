"""AI-assisted phishing analysis for MailSentry.

The module evaluates email body content, subject, links, and sender metadata for common
phishing patterns such as urgency, credential harvesting, and financial fraud.

It provides a deterministic local heuristic analysis by default so the prototype can run
without network access or API credentials, and it can optionally call an OpenAI-compatible
endpoint when configured.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


def heuristic_analysis(
    body_text: str,
    *,
    subject: str = "",
    links: Optional[List[str]] = None,
    sender_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Provide a deterministic fallback analysis using keyword heuristics."""
    text = f"{subject}\n{body_text}\n{' '.join(links or [])}".lower()

    urgency_terms = ["urgent", "immediately", "immediate", "act now", "verify now", "suspend"]
    financial_terms = ["invoice", "payment", "wire", "refund", "bank", "account balance"]
    credential_terms = ["password", "login", "username", "credential", "verify account", "click here", "verify your password"]
    spoofing_terms = ["executive", "ceo", "cfo", "hr manager", "board"]

    tactics: List[str] = []
    score = 5

    has_urgency = any(term in text for term in urgency_terms)
    has_credentials = any(term in text for term in credential_terms)
    has_financial = any(term in text for term in financial_terms)
    has_spoofing = any(term in text for term in spoofing_terms)

    if has_urgency:
        tactics.append("Urgency")
        score += 25

    if has_credentials:
        tactics.append("Credential Harvesting")
        score += 35

    if has_financial:
        tactics.append("Financial Fraud")
        score += 25

    if has_spoofing:
        tactics.append("Spoofing")
        score += 10

    if links:
        score += 10

    if sender_info and sender_info.get("display_name") and sender_info.get("from_domain"):
        score += 5

    if has_urgency and has_credentials:
        score += 20

    score = max(0, min(100, score))
    is_phishing = score >= 70 or (score >= 50 and len(tactics) >= 2)

    reasoning = (
        "The message contains multiple common phishing cues such as urgency and credential requests."
        if is_phishing
        else "No strong phishing indicators were detected."
    )

    return {
        "risk_score": score,
        "is_phishing": is_phishing,
        "detected_tactics": tactics or ["None detected"],
        "reasoning": reasoning,
        "source": "heuristic",
    }


def analyze_email_details(
    body_text: str,
    *,
    subject: str = "",
    links: Optional[List[str]] = None,
    sender_info: Optional[Dict[str, Any]] = None,
    llm_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Analyze an email and return a structured phishing-risk result."""
    links = links or []
    sender_info = sender_info or {}

    if llm_config is None:
        llm_config = {}

    endpoint = llm_config.get("endpoint") or os.getenv("OPENAI_API_BASE_URL")
    api_key = llm_config.get("api_key") or os.getenv("OPENAI_API_KEY")
    model = llm_config.get("model") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not endpoint or not api_key:
        return heuristic_analysis(body_text, subject=subject, links=links, sender_info=sender_info)

    prompt = (
        "Assess this email for phishing risk. Return compact JSON with keys: risk_score, is_phishing, detected_tactics, reasoning. "
        f"Subject: {subject}\nBody: {body_text}\nLinks: {json.dumps(links)}\nSender: {json.dumps(sender_info, sort_keys=True)}"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a strict email security classifier."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
    }

    try:
        import urllib.request

        request = urllib.request.Request(
            url=f"{endpoint.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            response_text = response.read().decode("utf-8")
            result = json.loads(response_text)
            content = result["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return {
                "risk_score": int(parsed.get("risk_score", 0)),
                "is_phishing": bool(parsed.get("is_phishing", False)),
                "detected_tactics": parsed.get("detected_tactics", []),
                "reasoning": parsed.get("reasoning", "No reasoning supplied"),
                "source": "llm",
            }
    except Exception as exc:  # pragma: no cover - network/endpoint dependent
        return {
            "risk_score": 0,
            "is_phishing": False,
            "detected_tactics": ["LLM fallback"],
            "reasoning": f"LLM call failed; using heuristic fallback: {exc}",
            "source": "fallback",
        }


def analyze_email(
    body_text: str,
    headers: Optional[Dict[str, str]] = None,
    sender_info: Optional[Dict[str, Any]] = None,
    llm_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Backward-compatible wrapper that accepts parsed header metadata."""
    subject = (headers or {}).get("Subject", "")
    links = []
    return analyze_email_details(
        body_text,
        subject=subject,
        links=links,
        sender_info=sender_info,
        llm_config=llm_config,
    )
