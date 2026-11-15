import json

from src.etl.extract import extract_urlhaus_data
from src.validation.validate import validate_records
from src.etl.transform import transform_urlhaus_data
from src.etl.features import extract_url_features
from src.etl.load import save_processed_data

from src.database.connection import Base, engine, SessionLocal
from src.database import schema
from src.database.repository import (
    save_urlhaus_records,
    save_openphish_record
)

from src.config import REJECTED_DIR

from src.apis.openphish import fetch_openphish_feed

from src.analysis.visualizations import (
    create_tld_chart,
    create_threat_chart,
    create_brand_chart,
    create_time_chart
)


def run_pipeline():
    print("Starting Scam Radar ETL Pipeline...")

    # 1. Create database tables
    Base.metadata.create_all(bind=engine)
    print("Database tables ready.")

    # 2. Extract URLhaus data
    records = extract_urlhaus_data()
    print(f"Extracted URLhaus records: {len(records)}")

    # 3. Validate URLhaus records
    valid_records, rejected_records = validate_records(records)

    print(f"Valid URLhaus records: {len(valid_records)}")
    print(f"Rejected URLhaus records: {len(rejected_records)}")

    # 4. Save rejected records
    REJECTED_DIR.mkdir(parents=True, exist_ok=True)

    rejected_path = REJECTED_DIR / "rejected_records.json"

    with open(rejected_path, "w", encoding="utf-8") as file:
        json.dump(
            rejected_records,
            file,
            indent=4,
            default=str
        )

    # 5. Transform URLhaus records
    df = transform_urlhaus_data(valid_records)
    df = extract_url_features(df)

    # 6. Export processed data
    save_processed_data(df)

    # 7. Save URLhaus records in SQLite
    db = SessionLocal()

    try:
        database_result = save_urlhaus_records(db, valid_records)
        print("URLhaus database result:", database_result)

    finally:
        db.close()

    # 8. Generate analysis charts
    if not df.empty:
        create_tld_chart(df)
        create_threat_chart(df)
        create_brand_chart(df)
        create_time_chart(df)

        print("Analysis charts generated.")

    else:
        print("No processed URLhaus data available for charts.")

    # 9. Extract OpenPhish feed
    print("\nFetching OpenPhish feed...")

    try:
        openphish_records = fetch_openphish_feed(limit=100)

        print(
            f"Extracted OpenPhish records: "
            f"{len(openphish_records)}"
        )

        openphish_saved = 0
        openphish_rejected = 0

        db = SessionLocal()

        try:
            for record in openphish_records:

                if not isinstance(record, dict):
                    openphish_rejected += 1
                    continue

                url = record.get("url")

                if not isinstance(url, str) or not url.strip():
                    openphish_rejected += 1
                    continue

                try:
                    save_openphish_record(db, url.strip())
                    openphish_saved += 1

                except ValueError:
                    db.rollback()
                    openphish_rejected += 1

        finally:
            db.close()

        print(f"OpenPhish saved: {openphish_saved}")
        print(f"OpenPhish rejected: {openphish_rejected}")

    except Exception as error:
        print(f"OpenPhish feed unavailable: {error}")
        print("Continuing with URLhaus data.")

    print("\nScam Radar ETL Pipeline completed!")


if __name__ == "__main__":
    run_pipeline()