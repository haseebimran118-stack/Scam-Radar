from urllib.parse import urlparse
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "bank",
    "wallet",
    "confirm"
]


def check_url_patterns(url: str) -> dict:
    """Check URL format and suspicious structural patterns."""

    url = url.strip()
    reasons = []
    score = 0

    if not url:
        return {
            "score": 0,
            "reasons": ["Please enter a URL"],
            "suspicious": False,
            "valid_format": False
        }

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if (
            parsed.scheme not in ["http", "https"]
            or not hostname
            or "." not in hostname
            or " " in url
        ):
            raise ValueError("Invalid URL format")

    except ValueError:
        return {
            "score": 0,
            "reasons": ["Invalid URL format"],
            "suspicious": False,
            "valid_format": False
        }

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL")

    if "@" in url:
        score += 20
        reasons.append("Contains @ symbol")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        score += 25
        reasons.append("Uses an IP address instead of a domain")

    if hostname.count(".") >= 4:
        score += 10
        reasons.append("Contains many subdomains")

    if "-" in hostname:
        score += 5
        reasons.append("Domain contains hyphens")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 5
            reasons.append(f"Contains suspicious keyword: {keyword}")

    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons,
        "suspicious": score >= 30,
        "valid_format": True
    }

def check_url(url: str) -> dict:
    return check_url_patterns(url)