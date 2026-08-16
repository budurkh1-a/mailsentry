import tempfile
import unittest
from pathlib import Path

from mailsentry.engine import scan_folder


class BatchScanTests(unittest.TestCase):
    def test_scan_folder_returns_multiple_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            first = Path(tmp_dir) / "a.eml"
            second = Path(tmp_dir) / "b.eml"
            first.write_text(
                "From: <ceo@external-example.com>\n"
                "Subject: Urgent password reset\n"
                "To: employee@securecorp.example\n"
                "\n"
                "Verify your password now: https://evil.example/login\n",
                encoding="utf-8",
            )
            second.write_text(
                "From: <ahmed@securecorp.example>\n"
                "Subject: Team sync\n"
                "To: employee@securecorp.example\n"
                "\n"
                "Hello team, the meeting is at 3 PM.\n",
                encoding="utf-8",
            )

            results = scan_folder(tmp_dir, internal_names=["Ahmed Al-Mansoor"], internal_titles=["CEO"], internal_domains=["securecorp.example"])

            self.assertEqual(len(results), 2)
            self.assertTrue(any(item["decision"] == "BLOCK" for item in results))
            self.assertTrue(any(item["decision"] == "PASS" for item in results))


if __name__ == "__main__":
    unittest.main()
