import unittest

from mailsentry.css_security import check_css_exfiltration
from mailsentry.engine import evaluate_email


class CssSecurityTests(unittest.TestCase):
    def test_css_exfiltration_patterns_are_detected(self) -> None:
        result = check_css_exfiltration(
            "<style>@import url(https://evil.example/x.css); @font-face { src: url(http://evil.example/f); } input[value^='a'] { color: red; }</style>"
        )
        self.assertTrue(result["is_suspicious"])
        self.assertGreaterEqual(len(result["matches"]), 4)

    def test_engine_blocks_css_exfiltration(self) -> None:
        report = evaluate_email(
            "From: security@securecorp.example\nSubject: Notice\nContent-Type: text/html\n\n"
            "<style>@import url(https://evil.example/style.css)</style><p>Review this notice.</p>",
            internal_domains=["securecorp.example"],
        )
        self.assertEqual(report["status"], "DANGER")
        self.assertEqual(report["verdict"], "SUSPICIOUS")
        self.assertEqual(report["decision"], "BLOCK")
        self.assertIn("Potential CSS Exfiltration (Outlook Exploit)", report["indicators"])


if __name__ == "__main__":
    unittest.main()
