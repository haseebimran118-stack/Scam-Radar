import unittest
from fastapi.testclient import TestClient

from src.api import app


client = TestClient(app)


class TestScamRadarAPI(unittest.TestCase):

    def test_home_endpoint(self):
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json())

    def test_health_endpoint(self):
        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["status"],
            "healthy"
        )


if __name__ == "__main__":
    unittest.main()