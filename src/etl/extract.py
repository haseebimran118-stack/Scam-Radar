from src.apis.urlhaus import fetch_recent_urls
from src.apis.openphish import check_openphish


def extract_urlhaus_data():
    """Fetch recent malicious URLs from URLhaus."""
    records = fetch_recent_urls()

    if not isinstance(records, list):
        raise RuntimeError("URLhaus returned an invalid dataset")

    return records


def extract_openphish_data(url: str):
    """Check a URL using OpenPhish."""
    return check_openphish(url)


if __name__ == "__main__":
    urls = extract_urlhaus_data()

    print(
        f"URLhaus records collected: {len(urls)}"
    )