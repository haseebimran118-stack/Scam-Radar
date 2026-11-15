import unittest

from src.validation.validate import validate_records


class TestValidation(unittest.TestCase):

    def test_valid_record(self):
        records = [{
            "url": "https://example.com/test",
            "host": "example.com",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["test"],
            "date_added": "2026-11-02 10:00:00"
        }]

        valid, rejected = validate_records(records)

        self.assertEqual(len(valid), 1)
        self.assertEqual(len(rejected), 0)

    def test_invalid_record(self):
        records = [{
            "url": "",
            "host": "example.com",
            "url_status": "online",
            "threat": "malware_download",
            "tags": [],
            "date_added": "2026-11-02 10:00:00"
        }]

        valid, rejected = validate_records(records)

        self.assertEqual(len(valid), 0)
        self.assertEqual(len(rejected), 1)


if __name__ == "__main__":
    unittest.main()