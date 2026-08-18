import unittest
from unittest.mock import patch

from mailsentry.engine import evaluate_email
from mailsentry.ai_analyzer import analyze_email_details


class FailSafePolicyTests(unittest.TestCase):
    def assert_unverified(self, result: dict) -> None:
        self.assertEqual(result["verdict"], "UNVERIFIED")
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["status"], "WARNING")
        self.assertEqual(result["decision"], "WARNING")
        self.assertIn("system error", result["details"].lower())
        self.assertIn("manual review", result["details"].lower())

    def test_header_parse_error_requires_manual_review(self) -> None:
        with patch("mailsentry.engine.parse_email", side_effect=TimeoutError("parser timed out")):
            self.assert_unverified(evaluate_email("From: sender@example.com\n\nBody"))

    def test_dns_error_requires_manual_review(self) -> None:
        with patch(
            "mailsentry.engine.evaluate_sender_authentication",
            return_value={"error": True, "details": "DNS lookup timed out"},
        ):
            self.assert_unverified(evaluate_email("From: sender@example.com\nSubject: test\n\nBody"))

    def test_ai_error_requires_manual_review(self) -> None:
        with patch(
            "mailsentry.engine.analyze_email_details",
            return_value={"error": True, "reasoning": "AI endpoint timed out"},
        ):
            self.assert_unverified(evaluate_email("From: sender@example.com\nSubject: test\n\nBody"))

    def test_langchain_failure_returns_neutral_schema(self) -> None:
        with patch("mailsentry.ai_analyzer._run_langchain_analysis", side_effect=TimeoutError("LLM timed out")):
            result = analyze_email_details(
                "Body",
                headers={"From": "sender@example.com"},
                authentication={"spf_pass": True, "dkim_pass": None},
                llm_config={"endpoint": "https://llm.example", "api_key": "test-key"},
            )
        self.assert_unverified(result)


if __name__ == "__main__":
    unittest.main()
