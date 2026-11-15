from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from src.database.connection import Base


class MaliciousURL(Base):
    __tablename__ = "malicious_urls"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, nullable=False, index=True)
    host = Column(String, nullable=False, index=True)
    url_status = Column(String, nullable=True)
    threat = Column(String, nullable=True)
    tags = Column(JSON, default=list)
    date_added = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    source = Column(String, nullable=False, default="URLhaus")


class URLStatusSnapshot(Base):
    __tablename__ = "url_status_snapshots"

    id = Column(Integer, primary_key=True, index=True)

    malicious_url_id = Column(
        Integer,
        ForeignKey("malicious_urls.id"),
        nullable=False,
        index=True
    )

    url_status = Column(String, nullable=False)
    observed_at = Column(DateTime, nullable=False)
