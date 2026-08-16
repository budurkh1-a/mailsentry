from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceStore:
    """Simple JSON-based store for email analysis history."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path or "history.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def _read(self) -> List[Dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, records: List[Dict[str, Any]]) -> None:
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, ensure_ascii=False)

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        records = self._read()
        enriched = dict(record)
        enriched.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        records.append(enriched)
        self._write(records)
        return enriched

    def list(self) -> List[Dict[str, Any]]:
        return self._read()

    def clear(self) -> None:
        self._write([])
