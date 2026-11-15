import pandas as pd


def analyze_url_data(df: pd.DataFrame) -> dict:
    """Analyze malicious URL patterns and possible brand impersonation."""

    if df.empty:
        return {
            "total_urls": 0,
            "top_tlds": {},
            "top_hosts": {},
            "top_threats": {},
            "top_tags": {},
            "top_brands": {},
            "status_counts": {}
        }

    def get_top_values(column):
        if column not in df.columns:
            return {}

        return (
            df[column]
            .dropna()
            .astype(str)
            .replace("", pd.NA)
            .dropna()
            .value_counts()
            .head(10)
            .to_dict()
        )

    top_tlds = get_top_values("tld")
    top_hosts = get_top_values("host")
    top_threats = get_top_values("threat")

    top_tags = {}
    if "tags" in df.columns:
        tags = df["tags"].apply(
            lambda value: value if isinstance(value, list) else []
        ).explode().dropna()

        top_tags = tags.value_counts().head(10).to_dict()

    top_brands = {}
    if "possible_brands" in df.columns:
        brands = df["possible_brands"].apply(
            lambda value: value if isinstance(value, list) else []
        ).explode().dropna()

        top_brands = brands.value_counts().head(10).to_dict()

    status_counts = get_top_values("url_status")

    return {
        "total_urls": len(df),
        "top_tlds": top_tlds,
        "top_hosts": top_hosts,
        "top_threats": top_threats,
        "top_tags": top_tags,
        "top_brands": top_brands,
        "status_counts": status_counts
    }