"""Decision engine for MailSentry.

This module integrates the parser, DNS checks, and AI analyzer into one end-to-end
pipeline and returns a JSON-friendly decision record for each email.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .ai_analyzer import analyze_email_details
from .css_security import check_css_exfiltration
from .dns_checker import evaluate_sender_authentication
from .fail_safe import unverified_result
from .parser import parse_email
from .storage import EvidenceStore
from .trust_lifecycle import TrustLifecycleManager
from .typosquatting import detect_typosquatting


_HISTORY_STORE = EvidenceStore("history.json")
_TRUST_MANAGER = TrustLifecycleManager("trust_lifecycle.json")


def evaluate_email(
    source: Any,
    *,
    internal_names: Optional[List[str]] = None,
    internal_titles: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
    llm_config: Optional[Dict[str, Any]] = None,
    message_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate a single email and return a final JSON summary log."""
    try:
        parsed = parse_email(source)
    except Exception as exc:
        result = unverified_result("header parsing", exc)
        _HISTORY_STORE.append(result)
        return result

    headers = parsed.headers
    from_header = headers.get("From", "")
    subject = headers.get("Subject", "")

    try:
        dns_result = evaluate_sender_authentication(
            from_header,
            internal_names=internal_names,
            internal_titles=internal_titles,
            internal_domains=internal_domains,
        )
        if dns_result.get("error"):
            raise RuntimeError(dns_result.get("details", "DNS/header authentication failed"))

        typosquatting_result = detect_typosquatting(from_header)
        css_exfiltration_result = check_css_exfiltration(parsed.html_body)

        ai_result = analyze_email_details(
            parsed.body_text,
            subject=subject,
            links=parsed.links,
            headers=headers,
            authentication={
                "spf_pass": dns_result.get("spf_pass"),
                "dkim_pass": dns_result.get("dkim_pass"),
                "dmarc_pass": dns_result.get("dmarc_pass"),
            },
            sender_info={
                "display_name": from_header,
                "from_domain": from_header.split("@", 1)[-1].strip(">") if "@" in from_header else "",
            },
            llm_config=llm_config,
        )
        if ai_result.get("error") or ai_result.get("verdict") == "UNVERIFIED":
            raise RuntimeError(ai_result.get("reasoning", "AI analysis failed"))
    except Exception as exc:
        result = unverified_result("DNS or AI analysis", exc, subject=subject, from_address=from_header)
        _HISTORY_STORE.append(result)
        return result

    ai_risk_score = int(ai_result.get("risk_score", 0))
    is_phishing = bool(ai_result.get("is_phishing", False))
    spf_pass = bool(dns_result.get("spf_pass", False))
    dmarc_pass = bool(dns_result.get("dmarc_pass", False))
    spoofed = bool(dns_result.get("is_display_name_spoofed", False))
    typosquatting = bool(typosquatting_result.get("is_suspicious", False))
    css_exfiltration = bool(css_exfiltration_result.get("is_suspicious", False))

    risk_score = ai_risk_score
    indicators: List[str] = []
    policy_hits: List[Dict[str, Any]] = []

    if not spf_pass:
        risk_score += 25
        indicators.append("SPF failed")
        policy_hits.append({"rule": "sender_auth_spf", "severity": "high", "detail": "Sender lacks a valid SPF record"})
    if not dmarc_pass:
        risk_score += 15
        indicators.append("DMARC failed")
        policy_hits.append({"rule": "sender_auth_dmarc", "severity": "medium", "detail": "Sender lacks a valid DMARC record"})
    if spoofed:
        risk_score += 20
        indicators.append("Display-name spoofing")
        policy_hits.append({"rule": "display_name_spoof", "severity": "high", "detail": "Display name appears to impersonate an internal identity"})
    if typosquatting:
        risk_score += 30
        indicators.append("SUSPICIOUS_TYPOSQUATTING")
        policy_hits.append({
            "rule": "domain_typosquatting",
            "severity": "high",
            "detail": f"Sender domain closely resembles {typosquatting_result['target_domain']} ({typosquatting_result['similarity']:.1%} similarity)",
        })
    if css_exfiltration:
        risk_score = max(risk_score + 40, 85)
        indicators.append("Potential CSS Exfiltration (Outlook Exploit)")
        policy_hits.append({
            "rule": "css_data_exfiltration",
            "severity": "critical",
            "detail": css_exfiltration_result["details"],
        })
    if is_phishing:
        risk_score += 10
        indicators.append("AI flagged as phishing")
        policy_hits.append({"rule": "ai_phish_signal", "severity": "high", "detail": "Content matches phishing heuristics"})
    if ai_risk_score >= 70:
        indicators.append("AI risk score >= 70")
        policy_hits.append({"rule": "risk_threshold", "severity": "medium", "detail": "Risk score exceeded the high-risk threshold"})

    if any(term in parsed.body_text.lower() for term in ["password", "verify", "click here", "urgent", "login"]):
        policy_hits.append({"rule": "credential_lure", "severity": "high", "detail": "Message uses credential-harvesting language"})

    risk_score = max(0, min(100, risk_score))

    if css_exfiltration or spoofed or not spf_pass or not dmarc_pass:
        decision = "BLOCK"
    elif risk_score >= 80 or is_phishing:
        decision = "BLOCK"
    elif risk_score >= 60:
        decision = "QUARANTINE"
    else:
        decision = "PASS"

    action = "QUARANTINE" if decision != "PASS" else "PASS"
    status = "DANGER" if css_exfiltration else "OK"
    verdict = "SUSPICIOUS" if css_exfiltration else "VERIFIED"
    risk_level = "critical" if risk_score >= 85 else "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low"
    reason = "; ".join(indicators) if indicators else "No suspicious indicators detected"
    threat_narrative = (
        "This message presents a credible phishing attempt because it combines sender authentication failures with credential-harvesting language and high-risk intent."
        if policy_hits
        else "The message does not appear to contain enough suspicious signals to warrant quarantine."
    )

    message_id = message_id or headers.get("Message-ID") or f"email-{abs(hash(from_header or headers.get('Subject', '')))}"
    fingerprint = f"{headers.get('Subject', '')}|{from_header}|{parsed.body_text[:200]}"
    lifecycle_entry = _TRUST_MANAGER.track_message(message_id, fingerprint=fingerprint, report={
        "decision": decision,
        "risk_score": risk_score,
        "reason": reason,
    })

    result = {
        "verdict": verdict,
        "status": status,
        "score": risk_score,
        "subject": headers.get("Subject", ""),
        "from_address": from_header,
        "decision": decision,
        "action": action,
        "reason": reason,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity": risk_level,
        "indicators": indicators,
        "policy_hits": policy_hits,
        "threat_narrative": threat_narrative,
        "spf_pass": spf_pass,
        "dmarc_pass": dmarc_pass,
        "spoofed": spoofed,
        "typosquatting": typosquatting_result,
        "css_exfiltration": css_exfiltration_result,
        "ai_risk_score": ai_risk_score,
        "ai_is_phishing": is_phishing,
        "ai_details": ai_result,
        "dns_details": dns_result,
        "trust_lifecycle": lifecycle_entry,
    }
    _HISTORY_STORE.append(result)
    return result


def scan_folder(folder_path: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Scan all .eml files in a folder and return a list of evaluation records."""
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    results: List[Dict[str, Any]] = []
    for path in sorted(folder.glob("*.eml")):
        results.append(evaluate_email(str(path), **kwargs))
    return results


def main() -> int:
    """CLI entry point for evaluating a folder of emails."""
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate a batch of email files")
    parser.add_argument("folder", nargs="?", default=".", help="Folder containing .eml files")
    parser.add_argument("--employee-name", dest="internal_names", action="append", default=[], help="Internal employee name")
    parser.add_argument("--title", dest="internal_titles", action="append", default=[], help="Internal title")
    parser.add_argument("--internal-domain", dest="internal_domains", action="append", default=[], help="Trusted internal domain")
    args = parser.parse_args()

    results = scan_folder(
        args.folder,
        internal_names=args.internal_names or None,
        internal_titles=args.internal_titles or None,
        internal_domains=args.internal_domains or None,
    )

    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
