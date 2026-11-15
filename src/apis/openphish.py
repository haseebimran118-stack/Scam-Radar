import requests


OPENPHISH_BASE_URL = "https://openphish.eu/api"


def check_openphish(url: str) -> dict:
    """Check a URL against the OpenPhish database."""

    try:
        response = requests.get(
            f"{OPENPHISH_BASE_URL}/check",
            params={"url": url},
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict):
            return {"error": "Unexpected API response"}

        return data

    except requests.exceptions.RequestException as error:
        return {"error": str(error)}

    except ValueError:
        return {"error": "Invalid JSON response"}


def fetch_openphish_feed(limit: int = 100) -> list:
    """Fetch verified phishing URLs from OpenPhish."""

    limit = max(1, min(limit, 1000))

    try:
        response = requests.get(
            f"{OPENPHISH_BASE_URL}/phish",
            params={
                "status": "verified",
                "limit": limit
            },
            timeout=30
        )

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, list):
            raise RuntimeError(
                "Unexpected OpenPhish feed response"
            )

        return data

    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"OpenPhish feed request failed: {error}"
        ) from error