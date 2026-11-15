import pandas as pd


def transform_urlhaus_data(records: list) -> pd.DataFrame:
    """Clean and standardize URLhaus records."""

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)

    required_columns = [
        "url",
        "host",
        "url_status",
        "threat",
        "tags",
        "date_added"
    ]

    for column in required_columns:
        if column not in df.columns:
            df[column] = None

    df = df[required_columns].copy()

    df["url"] = df["url"].astype("string").str.strip()
    df["host"] = (
        df["host"].astype("string").str.lower().str.strip()
    )

    df["tags"] = df["tags"].apply(
        lambda value: value if isinstance(value, list) else []
    )

    df = df.dropna(subset=["url", "host"])

    df = df[
        (df["url"] != "") &
        (df["host"] != "")
    ]

    df = df.drop_duplicates(subset=["url"])

    return df.reset_index(drop=True)