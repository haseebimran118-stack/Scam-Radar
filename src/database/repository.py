from urllib.parse import urlparse
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.database.schema import MaliciousURL, URLStatusSnapshot


def parse_date(value):
    """Convert an API date string into a Python datetime."""

    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).replace(tzinfo=None)

    except ValueError:
        return None


def save_urlhaus_records(db: Session, records: list):
    """Save URLhaus records and their status snapshots."""

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    saved_count = 0
    updated_count = 0
    snapshot_count = 0

    for record in records:
        url = record["url"]
        status = record.get("url_status") or "unknown"

        existing = (
            db.query(MaliciousURL)
            .filter(MaliciousURL.url == url)
            .first()
        )

        if existing:
            existing.url_status = status
            existing.threat = record.get("threat")
            existing.tags = record.get("tags") or []
            existing.last_seen = now
            malicious_url_id = existing.id
            updated_count += 1

        else:
            new_record = MaliciousURL(
                url=url,
                host=record["host"],
                url_status=status,
                threat=record.get("threat"),
                tags=record.get("tags") or [],
                date_added=parse_date(record.get("date_added")),
                first_seen=now,
                last_seen=now,
                source="URLhaus"
            )

            db.add(new_record)
            db.flush()

            malicious_url_id = new_record.id
            saved_count += 1

        snapshot = URLStatusSnapshot(
            malicious_url_id=malicious_url_id,
            url_status=status,
            observed_at=now
        )

        db.add(snapshot)
        snapshot_count += 1

    db.commit()

    return {
        "inserted": saved_count,
        "updated": updated_count,
        "snapshots": snapshot_count
    }


def save_openphish_record(db: Session, url: str):
    """Save a confirmed OpenPhish URL."""

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    parsed_url = urlparse(url)
    host = parsed_url.hostname

    if not host:
        raise ValueError("Invalid URL: hostname not found")

    existing = (
        db.query(MaliciousURL)
        .filter(MaliciousURL.url == url)
        .first()
    )

    if existing:
        existing.last_seen = now
        existing.threat = "Phishing"

        existing.tags = list(set((existing.tags or []) + ["OpenPhish"]))

        if existing.source and "OpenPhish" not in existing.source:
            existing.source += ", OpenPhish"

        record_id = existing.id

    else:
        new_record = MaliciousURL(
            url=url,
            host=host,
            url_status="unknown",
            threat="Phishing",
            tags=["OpenPhish"],
            first_seen=now,
            last_seen=now,
            source="OpenPhish"
        )

        db.add(new_record)
        db.flush()
        record_id = new_record.id

    db.add(
        URLStatusSnapshot(
            malicious_url_id=record_id,
            url_status="unknown",
            observed_at=now
        )
    )

    db.commit()