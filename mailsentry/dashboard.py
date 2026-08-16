"""CLI dashboard for MailSentry.

The dashboard reads evaluation results from the decision engine and prints a compact
summary table showing subject, sender, SPF status, spoofed status, AI score, and action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .engine import scan_folder


def print_summary(results: List[Dict[str, Any]]) -> None:
    """Print a polished CLI summary table."""
    print("MailSentry Batch Demo")
    print("=" * 120)
    print("{:<36} {:<32} {:<8} {:<8} {:<8} {:<12}".format(
        "Subject",
        "From",
        "SPF",
        "Spoofed",
        "AI",
        "Action",
    ))
    print("-" * 120)

    for result in results:
        print("{:<36} {:<32} {:<8} {:<8} {:<8} {:<12}".format(
            (result.get("subject") or "")[:36],
            (result.get("from_address") or "")[:32],
            "PASS" if result.get("spf_pass") else "FAIL",
            "YES" if result.get("spoofed") else "NO",
            str(result.get("ai_risk_score", "")),
            result.get("action", ""),
        ))

    print("-" * 120)
    print(f"Total: {len(results)} | PASS: {sum(1 for r in results if r.get('decision') == 'PASS')} | BLOCK: {sum(1 for r in results if r.get('decision') == 'BLOCK')}")


def main() -> int:
    """CLI entry point for scanning a folder and printing the summary table."""
    import argparse

    parser = argparse.ArgumentParser(description="Render a MailSentry CLI dashboard")
    parser.add_argument("folder", nargs="?", default="samples", help="Folder containing .eml files")
    parser.add_argument("--output", default=None, help="Optional JSON report output path")
    args = parser.parse_args()

    results = scan_folder(
        args.folder,
        internal_names=["Jane Doe", "CEO Executive"],
        internal_titles=["CEO", "HR Manager"],
        internal_domains=["company.example"],
    )
    print_summary(results)

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
