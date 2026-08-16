from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class TrustLifecycleManager:
    """Tracks trust state across a message lifecycle and re-evaluates when conditions change."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path or "trust_lifecycle.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def _read(self) -> List[Dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, records: List[Dict[str, Any]]) -> None:
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, ensure_ascii=False)

    def _state_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        decision = str(report.get("decision", "PASS")).upper()
        score = int(report.get("risk_score", 0))
        if decision == "BLOCK" or score >= 80:
            return {"trust_state": "compromised", "transition_reason": "content_change"}
        if decision == "QUARANTINE" or score >= 60:
            return {"trust_state": "suspicious", "transition_reason": "content_change"}
        return {"trust_state": "trusted", "transition_reason": None}

    def track_message(self, message_id: str, fingerprint: str, report: Dict[str, Any], event: Optional[str] = None) -> Dict[str, Any]:
        records = self._read()
        prior = next((item for item in reversed(records) if item.get("message_id") == message_id), None)
        state = self._state_from_report(report)

        if event in {"link_click", "attachment_open", "attachment_download"}:
            state = {"trust_state": "compromised", "transition_reason": "user_action"}
        elif prior and prior.get("fingerprint") != fingerprint:
            state = {"trust_state": "compromised", "transition_reason": "content_change"}
        elif prior and prior.get("trust_state") in {"compromised", "suspicious"}:
            state = {"trust_state": prior["trust_state"], "transition_reason": prior.get("transition_reason")}

        entry = {
            "message_id": message_id,
            "fingerprint": fingerprint,
            "event": event or "initial_scan",
            "trust_state": state["trust_state"],
            "transition_reason": state["transition_reason"],
            "report": report,
        }
        records.append(entry)
        self._write(records)
        return entry

    def get_state(self, message_id: str) -> Optional[Dict[str, Any]]:
        records = self._read()
        return next((item for item in reversed(records) if item.get("message_id") == message_id), None)

    def get_timeline(self, message_id: str) -> List[Dict[str, Any]]:
        records = self._read()
        return [item for item in records if item.get("message_id") == message_id]

    def clear(self) -> None:
        self._write([])
