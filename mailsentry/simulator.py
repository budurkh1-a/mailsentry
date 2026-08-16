"""Batch simulation for the MailSentry prototype.

This script creates a small batch of representative emails (legitimate, executive spoofing,
AI-driven phishing, and malicious links) and evaluates them. Results are written to a JSON file
for review and basic performance reporting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .engine import evaluate_email


def create_sample_emails() -> List[Dict[str, str]]:
    """Create a list of sample message payloads for simulation."""
    return [
        {
            "name": "legitimate",
            "content": "From: Jane Doe <jane@company.example>\nTo: team@company.example\nSubject: Weekly status update\nDate: Fri, 24 Jul 2026 10:00:00 +0000\n\nHello team,\nPlease review the attached status update before our weekly meeting.\n",
        },
        {
            "name": "executive_spoofing",
            "content": "From: CEO Executive <ceo@evil.example>\nTo: employee@company.example\nSubject: Urgent wire transfer needed\nDate: Fri, 24 Jul 2026 10:00:00 +0000\n\nThis is urgent. Please process the payment immediately and do not discuss it.\n",
        },
        {
            "name": "ai_phishing",
            "content": "From: Security Team <security@company.example>\nTo: employee@company.example\nSubject: Verify your password now\nDate: Fri, 24 Jul 2026 10:00:00 +0000\n\nYour account is at risk. Click here to verify your password and avoid suspension.\nhttps://phish.example/login\n",
        },
        {
            "name": "malicious_links",
            "content": "From: Finance <finance@company.example>\nTo: employee@company.example\nSubject: Invoice payment request\nDate: Fri, 24 Jul 2026 10:00:00 +0000\n\nPlease review the invoice and pay the attached amount.\nhttps://malicious.example/pay\n",
        },
    ]


def run_simulation(output_path: str = "simulation_results.json") -> Dict[str, object]:
    """Run the simulation and write a JSON report."""
    sample_emails = create_sample_emails()
    results: List[Dict[str, object]] = []

    for sample in sample_emails:
        report = evaluate_email(
            sample["content"],
            internal_employee_names=["Jane Doe", "CEO Executive"],
            internal_domains=["company.example"],
        )
        results.append({"name": sample["name"], "decision": report["decision"], "reason": report.get("quarantine_reason")})

    summary = {
        "total": len(results),
        "passed": sum(1 for item in results if item["decision"] == "PASS"),
        "blocked": sum(1 for item in results if item["decision"] == "BLOCK"),
        "results": results,
    }

    output_file = Path(output_path)
    output_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    """CLI entry point for the simulator."""
    import argparse

    parser = argparse.ArgumentParser(description="Simulate MailSentry against sample emails")
    parser.add_argument("--output", default="simulation_results.json", help="Path for the JSON report")
    args = parser.parse_args()

    summary = run_simulation(args.output)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
