import tempfile
import unittest
from pathlib import Path

from mailsentry.engine import evaluate_email


class EngineDecisionTests(unittest.TestCase):
    def _write_email(self, content: str) -> str:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_phishing_email_is_blocked(self) -> None:
        path = self._write_email(
            """From: <ceo@external-example.com>\n"
            "Subject: Urgent: Verify your password now\n"
            "To: employee@securecorp.example\n"
            "\n"
            "Hello, verify your password immediately to avoid account suspension.\n"
            "Click here: https://evil.example/login\n"
            """
        )
        try:
            result = evaluate_email(
                path,
                internal_names=["Ahmed Al-Mansoor"],
                internal_titles=["CEO"],
                internal_domains=["securecorp.example"],
            )
            self.assertEqual(result["decision"], "BLOCK")
            self.assertGreaterEqual(result["risk_score"], 80)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_legitimate_internal_email_passes(self) -> None:
        path = self._write_email(
            """From: <ahmed@securecorp.example>\n"
            "Subject: Team sync for today\n"
            "To: employee@securecorp.example\n"
            "\n"
            "Hi team, the meeting is at 3 PM and no action is required.\n"
            """
        )
        try:
            result = evaluate_email(
                path,
                internal_names=["Ahmed Al-Mansoor"],
                internal_titles=["CEO"],
                internal_domains=["securecorp.example"],
            )
            self.assertEqual(result["decision"], "PASS")
            self.assertLess(result["risk_score"], 60)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_policy_engine_exposes_rule_hits_and_narrative(self) -> None:
        path = self._write_email(
            """From: <ceo@external-example.com>\n"
            "Subject: Urgent password reset\n"
            "To: employee@securecorp.example\n"
            "\n"
            "Verify your password immediately and click here to continue.\n"
            """
        )
        try:
            result = evaluate_email(
                path,
                internal_names=["Ahmed Al-Mansoor"],
                internal_titles=["CEO"],
                internal_domains=["securecorp.example"],
            )
            self.assertGreaterEqual(len(result["policy_hits"]), 2)
            self.assertIn("credential", result["threat_narrative"].lower())
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
