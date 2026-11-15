import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{PROJECT_ROOT / 'data' / 'scam_radar.db'}"
)

APP_ENV = os.getenv("APP_ENV", "development")

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
REJECTED_DIR = DATA_DIR / "rejected"

for directory in [RAW_DIR, PROCESSED_DIR, REJECTED_DIR]:
    directory.mkdir(parents=True, exist_ok=True)