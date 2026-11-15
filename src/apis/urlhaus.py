import requests

from src.config import URLHAUS_AUTH_KEY


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_recent_urls():
    if not URLHAUS_AUTH_KEY:
        raise ValueError(
            "URLHAUS_AUTH_KEY is missing from .env"
        )

    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY
    }

    try:
        response = requests.get(
            URLHAUS_API_URL,
            headers=headers,
            timeout=30
        )

        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            raise RuntimeError(
                f"URLhaus API returned: {data.get('query_status')}"
            )

        urls = data.get("urls", [])

        if not isinstance(urls, list):
            raise RuntimeError("Unexpected URLhaus response format")

        return urls

    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"URLhaus request failed: {error}"
        ) from error