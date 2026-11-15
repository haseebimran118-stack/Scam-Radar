import unittest
import pandas as pd

from src.etl.features import extract_url_features


class TestFeatureExtraction(unittest.TestCase):

    def test_feature_columns(self):
        data = pd.DataFrame([{
            "url": "https://example.com/login",
            "host": "example.com"
        }])

        result = extract_url_features(data)

        self.assertIn("domain", result.columns)
        self.assertIn("tld", result.columns)
        self.assertIn("path_length", result.columns)
        self.assertIn("special_char_count", result.columns)


if __name__ == "__main__":
    unittest.main()