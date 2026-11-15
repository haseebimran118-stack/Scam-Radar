from pathlib import Path
from collections import Counter

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "reports"


def save_chart(filename):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    output_path = REPORTS_DIR / filename

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    print(f"Chart saved: {output_path}")


def create_tld_chart(df: pd.DataFrame):
    """Create a chart of the 10 most common TLDs."""

    if df.empty or "tld" not in df.columns:
        print("No TLD data available.")
        return

    counts = df["tld"].dropna().value_counts().head(10)

    if counts.empty:
        print("No TLD values available.")
        return

    plt.figure(figsize=(10, 6))
    counts.plot(kind="bar")
    plt.title("Top 10 TLDs in Malicious URLs")
    plt.xlabel("Top-Level Domain")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=45)

    save_chart("top_tlds.png")


def create_threat_chart(df: pd.DataFrame):
    """Create a chart of common threat types."""

    if df.empty or "threat" not in df.columns:
        print("No threat data available.")
        return

    counts = (
        df["threat"]
        .fillna("Unknown")
        .value_counts()
        .head(10)
    )

    if counts.empty:
        print("No threat values available.")
        return

    plt.figure(figsize=(10, 6))
    counts.plot(kind="bar")
    plt.title("Top Threat Types")
    plt.xlabel("Threat Type")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=45)

    save_chart("top_threats.png")


def create_brand_chart(df: pd.DataFrame):
    """Create a chart of possible brand-name matches."""

    if df.empty or "possible_brands" not in df.columns:
        print("No brand data available.")
        return

    brand_list = []

    for value in df["possible_brands"].tolist():

        if isinstance(value, list):
            brand_list.extend(
                str(brand).strip()
                for brand in value
                if brand and str(brand).strip()
            )

    if not brand_list:
        print("No possible brand matches found.")
        return

    counts = pd.Series(
        Counter(brand_list)
    ).sort_values(ascending=False).head(10)

    plt.figure(figsize=(10, 6))
    counts.plot(kind="bar")
    plt.title("Possible Brand Names in Malicious URLs")
    plt.xlabel("Brand Name")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=45)

    save_chart("top_brands.png")


def create_time_chart(df: pd.DataFrame):
    """Create a daily malicious URL reporting trend chart."""

    if df.empty or "date_added" not in df.columns:
        print("No date data available.")
        return

    data = df.copy()

    data["date_added"] = pd.to_datetime(
        data["date_added"],
        errors="coerce",
        utc=True
    )

    data = data.dropna(subset=["date_added"])

    if data.empty:
        print("No valid dates available.")
        return

    daily = (
        data.groupby(data["date_added"].dt.date)
        .size()
        .sort_index()
    )

    plt.figure(figsize=(12, 6))
    daily.plot(kind="line", marker="o")
    plt.title("Daily Malicious URL Reports")
    plt.xlabel("Date")
    plt.ylabel("Number of URLs")
    plt.xticks(rotation=45)

    save_chart("daily_reports.png")