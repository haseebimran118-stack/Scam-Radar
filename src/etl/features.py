from urllib.parse import urlparse
import pandas as pd
import re
import tldextract


BRAND_NAMES = [
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "netflix",
    "bank"
]


def extract_url_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract URL structure and possible impersonated brand names."""

    if df.empty:
        return df.copy()

    result = df.copy()

    def get_domain(url):
        try:
            return urlparse(str(url)).hostname or ""
        except (ValueError, TypeError):
            return ""

    def get_tld(domain):
        if not domain:
            return ""

        extracted = tldextract.extract(domain)
        return extracted.suffix

    def get_path_length(url):
        try:
            return len(urlparse(str(url)).path)
        except (ValueError, TypeError):
            return 0

    result["domain"] = result["url"].apply(get_domain)

    result["tld"] = result["domain"].apply(get_tld)

    result["path_length"] = result["url"].apply(get_path_length)

    result["special_char_count"] = result["url"].apply(
        lambda url: len(
            re.findall(r"[^a-zA-Z0-9]", str(url))
        )
    )

    result["url_length"] = (
        result["url"].astype(str).str.len()
    )

    def detect_brands(url):
        text = str(url).lower()

        return [
            brand for brand in BRAND_NAMES
            if brand in text
        ]

    result["possible_brands"] = (
        result["url"].apply(detect_brands)
    )

    return result