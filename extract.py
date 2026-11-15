
import requests

OPENPHISH_CHECK_URL = "https://openphish.eu/api/check"


def check_openphish(url):
    try:
        response = requests.get(
            OPENPHISH_CHECK_URL,
            params={"url": url},
            timeout=15
        )

        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as error:
        return {"error": str(error)}


def scan_url(url):
    print("\nScanning URL...")

    result = check_openphish(url)

    if "error" in result:
        print("Unable to check URL.")
        print("Error:", result["error"])

    elif result.get("found") is True:
        print("\nWARNING: Potential Phishing URL!")
        print("This URL was found in the OpenPhish database.")

    elif result.get("found") is False:
        print("\nURL not found in the phishing database.")
        print("This does NOT guarantee that the URL is safe.")

    else:
        print("Unexpected API response:", result)


if __name__ == "__main__":
    url = input("Enter URL to scan: ").strip()

    if url.startswith(("https://", "http://")):
        scan_url(url)
    else:
        print("Please enter a valid URL starting with http:// or https://")
