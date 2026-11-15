from pathlib import Path
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def save_processed_data(df: pd.DataFrame):
    """Save processed data as CSV and Parquet."""

    if df.empty:
        print("No records available to save.")
        return

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    csv_path = PROCESSED_DIR / "urlhaus_data.csv"
    parquet_path = PROCESSED_DIR / "urlhaus_data.parquet"

    # Save CSV
    df.to_csv(csv_path, index=False)
    print(f"CSV saved: {csv_path}")

    # Save Parquet
    try:
        df.to_parquet(parquet_path, index=False)
        print(f"Parquet saved: {parquet_path}")

    except Exception as error:
        print(f"Parquet export failed: {error}")