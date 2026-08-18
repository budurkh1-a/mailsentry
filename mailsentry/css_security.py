"""Detection of CSS injection and CSS data-exfiltration techniques in HTML email."""

from __future__ import annotations

import re
from typing import Any, Dict, List


CSS_EXFILTRATION_PATTERNS = {
    "External CSS URL call": r"url\s*\(\s*['\"]?https?://",
    "External stylesheet import": r"@import\b",
    "Custom font-face injection": r"@font-face\b",
    "Value attribute selector": r"(?:input\s*)?\[\s*value\s*(?:\^=|\$=|\*=|~=|\|=|=)",
}


def check_css_exfiltration(html_body: str) -> Dict[str, Any]:
    """Scan raw HTML email content for CSS token-exfiltration indicators."""
    matches: List[Dict[str, str]] = []
    for name, pattern in CSS_EXFILTRATION_PATTERNS.items():
        match = re.search(pattern, html_body or "", flags=re.IGNORECASE)
        if match:
            matches.append({"pattern": name, "match": match.group(0)})

    suspicious = bool(matches)
    details = (
        "Potential CSS Exfiltration (Outlook Exploit): " + ", ".join(item["pattern"] for item in matches)
        if suspicious
        else "No CSS data-exfiltration indicators detected"
    )
    return {"is_suspicious": suspicious, "matches": matches, "details": details}
