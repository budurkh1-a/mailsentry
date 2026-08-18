import unittest

from mailsentry.typosquatting import detect_typosquatting
from mailsentry.engine import evaluate_email


class TyposquattingTests(unittest.TestCase):
    def test_near_match_is_flagged(self) -> None:
        result = detect_typosquatting("Billing <notice@micros0ft.com>")
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(result["status"], "SUSPICIOUS_TYPOSQUATTING")
        self.assertEqual(result["target_domain"], "microsoft.com")
        self.assertGreater(result["similarity"], 0.80)

    def test_exact_target_domain_is_not_flagged(self) -> None:
        result = detect_typosquatting("Microsoft <alerts@microsoft.com>")
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["status"], "CLEAN")

    def test_engine_increases_risk_for_typosquatting(self) -> None:
        report = evaluate_email(
            "From: Microsoft Support <notice@micros0ft.com>\n"
            "Subject: Account notice\n\nPlease review your account.",
        )
        self.assertTrue(report["typosquatting"]["is_suspicious"])
        self.assertIn("SUSPICIOUS_TYPOSQUATTING", report["indicators"])
        self.assertGreaterEqual(report["risk_score"], 75)


if __name__ == "__main__":
    unittest.main()
