import tempfile
import unittest
from pathlib import Path

from mailsentry.engine import evaluate_email
from mailsentry.trust_lifecycle import TrustLifecycleManager


class TrustLifecycleTests(unittest.TestCase):
    def test_lifecycle_degrades_after_content_change(self) -> None:
        manager = TrustLifecycleManager(path=str(Path(tempfile.gettempdir()) / "trust_test.json"))
        manager.clear()

        initial = {
            "decision": "PASS",
            "risk_score": 20,
            "reason": "No suspicious indicators detected",
        }
        first = manager.track_message("demo-mail", fingerprint="abc", report=initial)
        self.assertEqual(first["trust_state"], "trusted")

        tampered = {
            "decision": "BLOCK",
            "risk_score": 90,
            "reason": "SPF failed; credential lure",
        }
        second = manager.track_message("demo-mail", fingerprint="xyz", report=tampered)
        self.assertEqual(second["trust_state"], "compromised")
        self.assertEqual(second["transition_reason"], "content_change")

    def test_lifecycle_degrades_after_user_action(self) -> None:
        manager = TrustLifecycleManager(path=str(Path(tempfile.gettempdir()) / "trust_test_user.json"))
        manager.clear()

        initial = {"decision": "PASS", "risk_score": 20, "reason": "No suspicious indicators detected"}
        first = manager.track_message("demo-mail-2", fingerprint="abc", report=initial)
        second = manager.track_message("demo-mail-2", fingerprint="abc", report=initial, event="link_click")
        self.assertEqual(second["trust_state"], "compromised")
        self.assertEqual(second["transition_reason"], "user_action")

    def test_engine_exposes_lifecycle_state(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False, encoding="utf-8") as handle:
            handle.write("From: <ahmed@securecorp.example>\nSubject: Team sync\n\nHello team.\n")
            path = handle.name
        try:
            result = evaluate_email(path, internal_names=["Ahmed Al-Mansoor"], internal_titles=["CEO"], internal_domains=["securecorp.example"], message_id="engine-lifecycle")
            self.assertIn("trust_lifecycle", result)
            self.assertIn("trust_state", result["trust_lifecycle"])
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
