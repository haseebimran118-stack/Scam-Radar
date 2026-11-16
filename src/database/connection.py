
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    if os.getenv("VERCEL"):
        raise RuntimeError(
            "DATABASE_URL is missing in Vercel environment variables."
        )

    DATABASE_URL = (
        f"sqlite:///{PROJECT_ROOT / 'data' / 'scam_radar.db'}"
    )

if DATABASE_URL.startswith("sqlite"):
    db_path = PROJECT_ROOT / "data" / "scam_radar.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
