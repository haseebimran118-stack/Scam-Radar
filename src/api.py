from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from src.checker.url_checker import check_url
from src.checker.risk_score import classify_risk
from src.apis.openphish import check_openphish
from src.database.connection import get_db
from src.database.schema import MaliciousURL


app = FastAPI(
    title="Scam Radar API",
    description="Malicious URL detection and risk analysis API",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: HttpUrl


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    if port and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        hostname = f"{hostname}:{port}"

    path = parsed.path or "/"

    return urlunparse((
        scheme,
        hostname,
        path,
        "",
        parsed.query,
        ""
    ))


def serialize_record(record):
    tags = record.tags or []

    if isinstance(tags, str):
        try:
            import json
            tags = json.loads(tags)
        except (ValueError, TypeError):
            tags = [tags] if tags else []

    return {
        "id": record.id,
        "url": record.url,
        "host": record.host,
        "url_status": record.url_status,
        "threat": record.threat,
        "tags": tags,
        "date_added": (
            record.date_added.isoformat()
            if record.date_added else None
        ),
        "first_seen": (
            record.first_seen.isoformat()
            if record.first_seen else None
        ),
        "last_seen": (
            record.last_seen.isoformat()
            if record.last_seen else None
        ),
        "source": record.source
    }


def find_database_record(db: Session, url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return None

    candidates = (
        db.query(MaliciousURL)
        .filter(MaliciousURL.host == hostname)
        .all()
    )

    normalized_input = normalize_url(url)

    for record in candidates:
        if normalize_url(record.url) == normalized_input:
            return record

    return None


@app.get("/")
def home():
    return {
        "message": "Scam Radar API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    try:
        records = db.query(MaliciousURL).all()

        total_urls = len(records)
        high_risk = 0

        threat_counts = Counter()
        source_names = set()

        today = datetime.now().date()

        last_seven_days = {
            today - timedelta(days=i): 0
            for i in range(6, -1, -1)
        }

        for record in records:
            try:
                result = check_url(record.url)
                risk = classify_risk(result.get("score", 0))

                if risk["level"] == "High":
                    high_risk += 1

            except Exception:
                pass

            threat_counts[record.threat or "Unknown"] += 1

            if record.source:
                for source in record.source.split(","):
                    source_names.add(source.strip())

            report_date = record.date_added or record.first_seen

            if report_date:
                report_day = report_date.date()

                if report_day in last_seven_days:
                    last_seven_days[report_day] += 1

        weekly_activity = [
            {
                "date": day.isoformat(),
                "name": day.strftime("%a"),
                "threats": count
            }
            for day, count in last_seven_days.items()
        ]

        top_threats = [
            {"name": name, "count": count}
            for name, count in threat_counts.most_common(10)
        ]

        return {
            "total_urls": total_urls,
            "confirmed_malicious_urls": total_urls,
            "high_risk_threats": high_risk,
            "sources_connected": len(source_names),
            "weekly_activity": weekly_activity,
            "top_threats": top_threats,
            "database": "SQLite",
            "status": "healthy"
        }

    except Exception as error:
        print("Dashboard error:", error)
        raise HTTPException(
            status_code=500,
            detail="Could not load dashboard data."
        )


@app.get("/threat-analysis")
def threat_analysis(db: Session = Depends(get_db)):
    try:
        records = db.query(MaliciousURL).all()

        threat_counts = Counter()
        source_counts = Counter()
        host_counts = Counter()
        tld_counts = Counter()
        status_counts = Counter()

        for record in records:
            threat_counts[record.threat or "Unknown"] += 1
            status_counts[record.url_status or "Unknown"] += 1

            if record.source:
                for source in record.source.split(","):
                    source_counts[source.strip()] += 1

            hostname = record.host or ""

            if hostname:
                host_counts[hostname] += 1

                parts = hostname.split(".")
                if len(parts) >= 2:
                    tld_counts[parts[-1].lower()] += 1

        return {
            "total_urls": len(records),
            "threat_types": [
                {"name": name, "count": count}
                for name, count in threat_counts.most_common(15)
            ],
            "sources": [
                {"name": name, "count": count}
                for name, count in source_counts.most_common(10)
            ],
            "top_hosts": [
                {"name": name, "count": count}
                for name, count in host_counts.most_common(10)
            ],
            "top_tlds": [
                {"name": name, "count": count}
                for name, count in tld_counts.most_common(10)
            ],
            "url_statuses": [
                {"name": name, "count": count}
                for name, count in status_counts.most_common(10)
            ]
        }

    except Exception as error:
        print("Threat analysis error:", error)
        raise HTTPException(
            status_code=500,
            detail="Could not load threat analysis."
        )


@app.get("/database")
def database_records(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", max_length=300),
    threat: str = Query("", max_length=100),
    source: str = Query("", max_length=100),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(MaliciousURL)

        if search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                (MaliciousURL.url.ilike(term))
                | (MaliciousURL.host.ilike(term))
                | (MaliciousURL.threat.ilike(term))
            )

        if threat.strip():
            query = query.filter(
                MaliciousURL.threat == threat.strip()
            )

        if source.strip():
            query = query.filter(
                MaliciousURL.source.ilike(f"%{source.strip()}%")
            )

        total = query.count()

        records = (
            query
            .order_by(MaliciousURL.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
            "records": [
                serialize_record(record)
                for record in records
            ]
        }

    except Exception as error:
        print("Database error:", error)
        raise HTTPException(
            status_code=500,
            detail="Could not load database records."
        )


@app.post("/check")
def check_malicious_url(
    request: URLRequest,
    db: Session = Depends(get_db)
):
    url = str(request.url)

    try:
        local_result = check_url(url)
        database_record = find_database_record(db, url)

        if database_record:
            database_result = {
                "found": True,
                "source": database_record.source,
                "threat": database_record.threat,
                "url_status": database_record.url_status,
                "tags": serialize_record(database_record)["tags"]
            }
        else:
            database_result = {
                "found": False,
                "source": None,
                "threat": None,
                "url_status": None,
                "tags": []
            }

        openphish_result = check_openphish(url)

        return {
            "url": url,
            "local_analysis": local_result,
            "database_analysis": database_result,
            "openphish_analysis": openphish_result
        }

    except Exception as error:
        print("URL checking error:", error)
        raise HTTPException(
            status_code=500,
            detail="URL checking failed. Please try again."
        )