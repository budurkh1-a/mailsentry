"""LangChain-backed phishing analysis for MailSentry."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Literal, Optional

from .fail_safe import unverified_result

try:
    from langchain_core.output_parsers import PydanticOutputParser
    from langchain_core.prompts import PromptTemplate
    from langchain_openai import ChatOpenAI
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover
    ChatOpenAI = PromptTemplate = PydanticOutputParser = None  # type: ignore[assignment]
    BaseModel = object  # type: ignore[assignment,misc]
    def Field(*_args: Any, **_kwargs: Any) -> None:  # type: ignore[misc]
        return None


class EmailAnalysisSchema(BaseModel):
    """The response contract enforced by LangChain's Pydantic output parser."""

    verdict: Literal["PHISHING", "SUSPICIOUS", "CLEAN", "UNVERIFIED"]
    risk_score: int = Field(ge=0, le=100)
    reasoning: str
    indicators: List[str]


ANALYSIS_PROMPT = """You are an email security analyst. Use only the supplied evidence.
Do not interpret unavailable authentication results as failures.

Email headers: {headers}
Email body: {body}
Extracted links: {links}
Sender authentication (SPF/DKIM/DMARC): {authentication}

{format_instructions}
"""


def _with_legacy_fields(analysis: Dict[str, Any], *, source: str) -> Dict[str, Any]:
    """Retain fields consumed by the existing decision engine and dashboard."""
    analysis["is_phishing"] = analysis["verdict"] == "PHISHING"
    analysis["detected_tactics"] = analysis["indicators"] or ["None detected"]
    analysis["source"] = source
    return analysis


def heuristic_analysis(body_text: str, *, subject: str = "", links: Optional[List[str]] = None,
                       sender_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic local analysis for deployments without an LLM configuration."""
    text = f"{subject}\n{body_text}\n{' '.join(links or [])}".lower()
    rules = [
        ("Urgency", ["urgent", "immediately", "act now", "verify now", "suspend"], 25),
        ("Credential Harvesting", ["password", "login", "username", "credential", "verify account", "click here"], 35),
        ("Financial Fraud", ["invoice", "payment", "wire", "refund", "bank"], 25),
        ("Spoofing", ["executive", "ceo", "cfo", "hr manager", "board"], 10),
    ]
    indicators: List[str] = []
    score = 5
    for indicator, terms, weight in rules:
        if any(term in text for term in terms):
            indicators.append(indicator)
            score += weight
    if links:
        indicators.append("Embedded links")
        score += 10
    if sender_info and sender_info.get("display_name") and sender_info.get("from_domain"):
        score += 5
    if "Urgency" in indicators and "Credential Harvesting" in indicators:
        score += 20
    score = max(0, min(100, score))
    verdict = "PHISHING" if score >= 70 else "SUSPICIOUS" if score >= 50 else "CLEAN"
    reasoning = "The message contains multiple phishing cues." if verdict == "PHISHING" else "No strong phishing indicators were detected."
    return _with_legacy_fields({"verdict": verdict, "risk_score": score, "reasoning": reasoning, "indicators": indicators}, source="heuristic")


def _run_langchain_analysis(*, endpoint: str, api_key: str, model: str, headers: Dict[str, str],
                            body_text: str, links: List[str], authentication: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke ChatOpenAI through a PromptTemplate and PydanticOutputParser chain."""
    if not all([ChatOpenAI, PromptTemplate, PydanticOutputParser]):
        raise RuntimeError("LangChain dependencies are not installed")
    parser = PydanticOutputParser(pydantic_object=EmailAnalysisSchema)
    prompt = PromptTemplate(
        template=ANALYSIS_PROMPT,
        input_variables=["headers", "body", "links", "authentication"],
        partial_variables={"format_instructions": parser.get_format_instructions()},
    )
    llm = ChatOpenAI(model=model, api_key=api_key, base_url=endpoint, temperature=0)
    parsed = (prompt | llm | parser).invoke({
        "headers": json.dumps(headers, sort_keys=True), "body": body_text,
        "links": json.dumps(links), "authentication": json.dumps(authentication, sort_keys=True),
    })
    return parsed.model_dump() if hasattr(parsed, "model_dump") else parsed.dict()


def analyze_email_details(body_text: str, *, subject: str = "", links: Optional[List[str]] = None,
                          sender_info: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
                          authentication: Optional[Dict[str, Any]] = None,
                          llm_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a schema-validated LangChain result or the neutral error result."""
    links, sender_info, authentication, llm_config = links or [], sender_info or {}, authentication or {}, llm_config or {}
    headers = {**(headers or {}), "Subject": subject}
    endpoint = llm_config.get("endpoint") or os.getenv("OPENAI_API_BASE_URL")
    api_key = llm_config.get("api_key") or os.getenv("OPENAI_API_KEY")
    model = llm_config.get("model") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if not endpoint or not api_key:
        return heuristic_analysis(body_text, subject=subject, links=links, sender_info=sender_info)
    try:
        analysis = _run_langchain_analysis(endpoint=endpoint, api_key=api_key, model=model, headers=headers,
                                            body_text=body_text, links=links, authentication=authentication)
        return _with_legacy_fields(analysis, source="langchain")
    except Exception as exc:  # Includes LLM, network, and output-parser failures.
        return unverified_result("LangChain AI analysis", exc)


def analyze_email(body_text: str, headers: Optional[Dict[str, str]] = None,
                  sender_info: Optional[Dict[str, Any]] = None,
                  llm_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Backward-compatible wrapper accepting parsed headers."""
    return analyze_email_details(body_text, subject=(headers or {}).get("Subject", ""), headers=headers,
                                 sender_info=sender_info, llm_config=llm_config)
