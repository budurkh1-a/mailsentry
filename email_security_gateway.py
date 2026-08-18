"""Email Security Gateway (ESG) for phishing, spoofing, and malicious-context detection.

This module accepts either a path to an RFC 822 email file (.eml) or raw email text,
parses the message, inspects headers/body/attachments, performs lightweight SPF/DMARC
checks, evaluates identity spoofing indicators, and produces a pass/block decision.

The implementation is intentionally modular and includes clear separation between parsing,
classification, and decision logic. It is designed to be easy to extend with a real
LLM endpoint or a production-grade DNS-based SPF/DMARC evaluator.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mailsentry.fail_safe import system_error_details, unverified_result

try:
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dns = None  # type: ignore


class EmailSecurityError(Exception):
    """Raised when the input email cannot be parsed or processed."""


def load_email_source(source: Any) -> Tuple[bytes, str]:
    """Load an email from a file path or raw text content.

    Args:
        source: A file path, bytes payload, or raw RFC 822 text.

    Returns:
        A tuple of (raw_bytes, source_label).
    """
    if isinstance(source, bytes):
        return source, "raw-bytes"

    if isinstance(source, str):
        if os.path.exists(source):
            path = Path(source)
            if not path.is_file():
                raise EmailSecurityError(f"Path is not a file: {source}")
            return path.read_bytes(), str(path)

        if "From:" in source or "Subject:" in source or "\n" in source:
            return source.encode("utf-8", errors="replace"), "raw-text"

        raise EmailSecurityError(
            "Input string does not look like a file path or raw RFC 822 content"
        )

    raise EmailSecurityError("Unsupported email source type")


def parse_email(source: Any) -> Any:
    """Parse an RFC 822 email using the standard library email parser."""
    raw_bytes, _ = load_email_source(source)
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)


def extract_headers(message: Any) -> Dict[str, str]:
    """Return message headers as a flat dictionary."""
    return {key: value for key, value in message.items()}


def strip_html(text: str) -> str:
    """Very lightweight HTML stripping for analysis purposes."""
    return re.sub(r"<[^>]+>", " ", text)


def extract_body(message: Any) -> Dict[str, Any]:
    """Extract visible text content and collect attachment metadata."""
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()

        if content_disposition == "attachment":
            payload = part.get_payload(decode=True)
            attachments.append(
                {
                    "filename": part.get_filename() or "unnamed",
                    "content_type": content_type,
                    "size_bytes": len(payload or b""),
                }
            )
            continue

        if content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            plain_parts.append(payload.decode(charset, errors="replace"))
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            html_parts.append(strip_html(payload.decode(charset, errors="replace")))

    body_text = "\n".join(plain_parts).strip()
    if not body_text and html_parts:
        body_text = "\n".join(html_parts).strip()

    return {
        "plain_text": body_text,
        "html_text": "\n".join(html_parts).strip(),
        "attachments": attachments,
    }


def extract_sender_info(message: Any) -> Dict[str, Any]:
    """Extract sender-related information from the message."""
    headers = extract_headers(message)
    from_header = headers.get("From", "")

    display_name = ""
    from_address = ""
    if from_header:
        parsed_addresses = []
        try:
            from email.utils import getaddresses

            parsed_addresses = getaddresses([from_header])
        except Exception as exc:  # pragma: no cover - defensive fallback
            raise EmailSecurityError(f"From header parsing failed: {exc}") from exc

        if parsed_addresses:
            display_name, from_address = parsed_addresses[0]

    sender_ip = extract_sender_ip(message)
    from_domain = extract_domain(from_address)
    sender_domain = extract_domain(headers.get("Return-Path", from_address))

    return {
        "from_header": from_header,
        "display_name": display_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "received_headers": message.get_all("Received", []),
    }


def extract_sender_ip(message: Any) -> Optional[str]:
    """Extract a sender IP from Received headers when available."""
    received_headers = message.get_all("Received", [])
    for header in reversed(received_headers):
        matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header)
        if matches:
            return matches[-1]
    return None


def extract_domain(address: str) -> str:
    """Extract domain from an email address or a Return-Path value."""
    if not address:
        return ""
    candidate = address.strip()
    if "@" in candidate:
        candidate = candidate.split("@", 1)[1]
    candidate = candidate.replace("<", "").replace(">", "")
    candidate = candidate.split("[", 1)[0].strip()
    return candidate.lower()


def normalize_name(value: str) -> str:
    """Lowercase and collapse whitespace for comparison purposes."""
    return re.sub(r"\s+", " ", value).strip().lower()


def detect_identity_spoofing(
    sender_info: Dict[str, Any],
    internal_employee_names: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Detect identity spoofing by comparing a display name to known employee names.

    A simple heuristic is used: if the From address is external and the display name
    resembles an internal employee name, it is considered suspicious.
    """
    employee_names = internal_employee_names or []
    internal_domains = internal_domains or []

    display_name = sender_info.get("display_name", "")
    from_domain = sender_info.get("from_domain", "")
    from_address = sender_info.get("from_address", "")

    is_external_from = bool(from_domain) and from_domain not in internal_domains
    name_matches = False
    if display_name and employee_names:
        normalized_display = normalize_name(display_name)
        for employee_name in employee_names:
            if normalize_name(employee_name) in normalized_display:
                name_matches = True
                break

    detected = bool(is_external_from and name_matches and from_address)
    return {
        "detected": detected,
        "reason": (
            "Display name matches an internal employee name while the sender address is external"
            if detected
            else "No obvious identity spoofing indicators detected"
        ),
    }


def _query_txt_records(domain: str) -> List[str]:
    """Return TXT records for a domain when dnspython is available."""
    if dns is None:
        # Optional DNS support is a configured capability, not a failed lookup.
        return []

    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:
        raise EmailSecurityError(f"DNS TXT lookup failed for {domain}: {exc}") from exc

    return [answer.to_text() for answer in answers]


def verify_spf(sender_ip: Optional[str], domain: str) -> Dict[str, Any]:
    """Perform a lightweight SPF check.

    The implementation uses DNS TXT records when dnspython is available. If the record
    is absent or the dependency is missing, the result is marked as failed/unknown.
    """
    if not sender_ip or not domain:
        return {
            "passed": False,
            "reason": "Sender IP or domain missing",
            "record": None,
        }

    records = _query_txt_records(domain)
    spf_records = [record for record in records if record.startswith('"v=spf1') or record.startswith("v=spf1")]
    if not spf_records:
        return {
            "passed": False,
            "reason": "No SPF record found",
            "record": None,
        }

    record = spf_records[0].strip('"')
    if "all" not in record:
        return {
            "passed": False,
            "reason": "SPF record missing an all mechanism",
            "record": record,
        }

    # Lightweight heuristic: a record exists and contains an all mechanism.
    # This is intentionally simple and meant to be extended in production.
    return {
        "passed": True,
        "reason": "SPF record present",
        "record": record,
    }


def verify_dmarc(domain: str) -> Dict[str, Any]:
    """Perform a lightweight DMARC check using DNS TXT records."""
    if not domain:
        return {
            "passed": False,
            "reason": "Domain missing",
            "record": None,
        }

    dmarc_domain = f"_dmarc.{domain}"
    records = _query_txt_records(dmarc_domain)
    dmarc_records = [record for record in records if record.startswith('"v=DMARC1') or record.startswith("v=DMARC1")]
    if not dmarc_records:
        return {
            "passed": False,
            "reason": "No DMARC record found",
            "record": None,
        }

    record = dmarc_records[0].strip('"')
    policy = "none"
    for item in record.split(";"):
        if item.strip().startswith("p="):
            policy = item.strip().split("=", 1)[1].lower()
            break

    passed = policy in {"quarantine", "reject"}
    return {
        "passed": passed,
        "reason": f"DMARC policy is {policy}",
        "record": record,
    }


def heuristic_ai_analysis(body_text: str, sender_info: Dict[str, Any]) -> Dict[str, Any]:
    """Provide a deterministic local fallback analysis when no external LLM is configured."""
    lowered = (body_text or "").lower()

    urgency_terms = ["urgent", "immediately", "act now", "verify now", "suspend"]
    financial_terms = ["invoice", "payment", "wire", "refund", "bank", "account balance"]
    credential_terms = ["password", "login", "credential", "username", "click here", "verify account"]

    intent = "Benign"
    score = 10

    if any(term in lowered for term in credential_terms):
        intent = "Credential Harvesting"
        score += 35
    if any(term in lowered for term in financial_terms):
        intent = "Financial"
        score += 25
    if any(term in lowered for term in urgency_terms):
        intent = "Urgency"
        score += 20

    if sender_info.get("display_name") and sender_info.get("from_domain"):
        score += 10

    score = min(100, score)

    reasoning = (
        "Heuristic analysis flagged suspicious language and sender context. "
        f"Risk score {score}/100 derived from urgency, financial cues, and credential-themed wording."
    )

    return {
        "intent": intent,
        "risk_score": score,
        "reasoning": reasoning,
        "source": "heuristic",
    }


def analyze_with_llm(
    body_text: str,
    sender_info: Dict[str, Any],
    llm_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Send the message context to an LLM endpoint when configuration is provided.

    The function attempts a generic JSON POST to an OpenAI-compatible API if the
    environment variables OPENAI_API_KEY and OPENAI_API_BASE_URL are configured.
    If those values are absent, it falls back to the local heuristic analyzer.
    """
    if not llm_config:
        llm_config = {}

    endpoint = llm_config.get("endpoint") or os.getenv("OPENAI_API_BASE_URL")
    api_key = llm_config.get("api_key") or os.getenv("OPENAI_API_KEY")
    model = llm_config.get("model") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not endpoint or not api_key:
        return heuristic_ai_analysis(body_text, sender_info)

    prompt = (
        "Assess this email for phishing or spoofing risk. "
        "Return JSON with keys: intent, risk_score, reasoning. "
        f"Body: {body_text}\nSender: {json.dumps(sender_info, sort_keys=True)}"
    )

    payload = {
        "model": model,
        "messages": [{"role": "system", "content": "You are a strict email security classifier."}, {"role": "user", "content": prompt}],
        "temperature": 0.1,
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
            response_data = json.loads(response_text)
            choice = response_data["choices"][0]["message"]["content"]
            parsed = json.loads(choice)
            return {
                "intent": parsed.get("intent", "Unknown"),
                "risk_score": int(parsed.get("risk_score", 0)),
                "reasoning": parsed.get("reasoning", "No reasoning returned"),
                "source": "llm",
            }
    except Exception as exc:  # pragma: no cover - network dependent
        return {
            "intent": "Unknown",
            "risk_score": 50,
            "reasoning": system_error_details("AI analysis", exc),
            "source": "error",
            "error": True,
        }


def _evaluate_email(
    source: Any,
    *,
    internal_employee_names: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
    llm_config: Optional[Dict[str, Any]] = None,
    risk_threshold: int = 75,
) -> Dict[str, Any]:
    """Evaluate an email and return a JSON-compatible decision payload."""
    message = parse_email(source)
    headers = extract_headers(message)
    body_info = extract_body(message)
    sender_info = extract_sender_info(message)

    # Authentication checks
    spf_result = verify_spf(sender_info.get("sender_ip"), sender_info.get("from_domain") or sender_info.get("sender_domain", ""))
    dmarc_result = verify_dmarc(sender_info.get("from_domain") or sender_info.get("sender_domain", ""))

    # Identity spoofing check
    spoofing_result = detect_identity_spoofing(
        sender_info,
        internal_employee_names=internal_employee_names,
        internal_domains=internal_domains,
    )

    # AI analysis layer
    ai_result = analyze_with_llm(body_info.get("plain_text", ""), sender_info, llm_config=llm_config)
    if ai_result.get("error"):
        raise EmailSecurityError(ai_result["reasoning"])

    reasons: List[str] = []
    if not spf_result.get("passed", False):
        reasons.append("SPF verification failed")
    if not dmarc_result.get("passed", False):
        reasons.append("DMARC verification failed")
    if spoofing_result.get("detected", False):
        reasons.append("Identity spoofing detected")
    if ai_result.get("risk_score", 0) > risk_threshold:
        reasons.append(f"AI risk score {ai_result.get('risk_score')} exceeds threshold")

    decision = "BLOCK" if reasons else "PASS"

    return {
        "verdict": "VERIFIED",
        "status": "OK",
        "score": ai_result.get("risk_score", 0),
        "decision": decision,
        "reason": reasons[0] if reasons else "No suspicious indicators detected",
        "reasons": reasons,
        "headers": headers,
        "body": {
            "text": body_info.get("plain_text", ""),
            "attachments": body_info.get("attachments", []),
        },
        "sender": sender_info,
        "authentication": {
            "spf": spf_result,
            "dmarc": dmarc_result,
        },
        "identity_spoofing": spoofing_result,
        "ai_analysis": ai_result,
    }


def evaluate_email(
    source: Any,
    *,
    internal_employee_names: Optional[List[str]] = None,
    internal_domains: Optional[List[str]] = None,
    llm_config: Optional[Dict[str, Any]] = None,
    risk_threshold: int = 75,
) -> Dict[str, Any]:
    """Evaluate email, returning a neutral manual-review decision on any check error."""
    try:
        return _evaluate_email(
            source,
            internal_employee_names=internal_employee_names,
            internal_domains=internal_domains,
            llm_config=llm_config,
            risk_threshold=risk_threshold,
        )
    except Exception as exc:
        return unverified_result(
            "email analysis",
            exc,
            extra={
                "reasons": [system_error_details("email analysis", exc)],
                "authentication": {},
                "identity_spoofing": {},
                "ai_analysis": {},
            },
        )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(description="Evaluate a raw email for phishing and spoofing risk")
    parser.add_argument("email_source", help="Path to an .eml file or raw RFC 822 text")
    parser.add_argument("--employee-name", dest="employee_names", action="append", default=[], help="Internal employee name to detect spoofing")
    parser.add_argument("--internal-domain", dest="internal_domains", action="append", default=[], help="Internal domain to treat as trusted")
    parser.add_argument("--risk-threshold", type=int, default=75, help="AI risk threshold for blocking")
    return parser


def main() -> int:
    """CLI entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()

    result = evaluate_email(
        args.email_source,
        internal_employee_names=args.employee_names or None,
        internal_domains=args.internal_domains or None,
        risk_threshold=args.risk_threshold,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
