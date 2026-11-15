import unittest

from src.checker.url_checker import check_url_patterns
from src.checker.risk_score import classify_risk


class TestURLChecker(unittest.TestCase):

    def test_empty_url(self):
        result = check_url_patterns("")

        self.assertFalse(result["valid_format"])
        self.assertEqual(result["score"], 0)

    def test_valid_url_format(self):
        result = check_url_patterns("https://example.com")

        self.assertTrue(result["valid_format"])

    def test_suspicious_keyword(self):
        result = check_url_patterns(
            "https://example.com/login"
        )

        self.assertGreater(result["score"], 0)

    def test_risk_classification(self):
        result = classify_risk(75)

        self.assertEqual(result["level"], "High")


if __name__ == "__main__":
    unittest.main()