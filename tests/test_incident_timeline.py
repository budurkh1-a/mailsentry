import tempfile
import unittest
from pathlib import Path

from mailsentry.trust_lifecycle import TrustLifecycleManager


class IncidentTimelineTests(unittest.TestCase):
    def test_timeline_records_multiple_events(self) -> None:
        manager = TrustLifecycleManager(path=str(Path(tempfile.gettempdir()) / "timeline_test.json"))
        manager.clear()

        initial = manager.track_message("case-1", fingerprint="a", report={"decision": "PASS", "risk_score": 20, "reason": "ok"})
        changed = manager.track_message("case-1", fingerprint="b", report={"decision": "BLOCK", "risk_score": 90, "reason": "phish"})
        action = manager.track_message("case-1", fingerprint="b", report={"decision": "BLOCK", "risk_score": 90, "reason": "phish"}, event="link_click")

        self.assertEqual(initial["event"], "initial_scan")
        self.assertEqual(changed["transition_reason"], "content_change")
        self.assertEqual(action["transition_reason"], "user_action")


if __name__ == "__main__":
    unittest.main()
