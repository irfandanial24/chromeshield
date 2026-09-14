"""
Basic tests for ChromeShield.

Run from the project root with:
    python -m unittest discover -s tests

These tests check the core promise of the tool: a benign extension should
score LOW, and a malicious one should score HIGH. They also confirm specific
dangerous behaviours are actually detected.
"""

import unittest
from pathlib import Path

from chromeshield import scan

ROOT = Path(__file__).resolve().parent.parent
BENIGN = ROOT / "samples" / "benign_extension"
MALICIOUS = ROOT / "samples" / "malicious_extension"


class TestChromeShield(unittest.TestCase):

    def test_benign_scores_low(self):
        report = scan(BENIGN)
        self.assertIn(report.level, ("MINIMAL", "LOW"),
                      f"benign extension scored too high: {report.score}")

    def test_malicious_scores_high(self):
        report = scan(MALICIOUS)
        self.assertEqual(report.level, "HIGH",
                         f"malicious extension only scored {report.score}")

    def test_malicious_detects_cookies(self):
        report = scan(MALICIOUS)
        names = {f.name for f in report.findings}
        self.assertIn("cookies", names)

    def test_malicious_detects_eval(self):
        report = scan(MALICIOUS)
        names = {f.name for f in report.findings}
        self.assertIn("eval()", names)

    def test_malicious_detects_all_urls(self):
        report = scan(MALICIOUS)
        names = {f.name for f in report.findings}
        self.assertIn("<all_urls>", names)

    def test_malicious_higher_than_benign(self):
        self.assertGreater(scan(MALICIOUS).score, scan(BENIGN).score)


if __name__ == "__main__":
    unittest.main()
