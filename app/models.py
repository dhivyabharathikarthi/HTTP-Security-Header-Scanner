"""SQLAlchemy database models for scan results persistence."""

from datetime import datetime, timezone
import json
from .database import Base, HAS_SQLALCHEMY

if HAS_SQLALCHEMY:
    from sqlalchemy import Column, String, Integer, DateTime, Text

    class ScanRecord(Base):
        """Represents a completed security header scan stored in SQLite via SQLAlchemy."""

        __tablename__ = "scans"

        id = Column(String(36), primary_key=True, index=True)
        original_url = Column(String(2048), nullable=False, index=True)
        final_url = Column(String(2048), nullable=False)
        timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
        status_code = Column(Integer, nullable=False)
        score = Column(Integer, nullable=False)
        max_score = Column(Integer, nullable=False)
        result_json = Column(Text, nullable=False)

        def to_dict(self):
            """Converts the scan record to a Python dictionary."""
            return {
                "id": self.id,
                "original_url": self.original_url,
                "final_url": self.final_url,
                "timestamp": self.timestamp.isoformat() if self.timestamp else None,
                "status_code": self.status_code,
                "score": self.score,
                "max_score": self.max_score,
                "scan_data": json.loads(self.result_json) if self.result_json else {}
            }
else:
    class ScanRecord:
        """Lightweight scan record representation for stdlib sqlite3 environments."""

        def __init__(self, id, original_url, final_url, timestamp, status_code, score, max_score, result_json):
            self.id = id
            self.original_url = original_url
            self.final_url = final_url
            self.timestamp = timestamp
            self.status_code = status_code
            self.score = score
            self.max_score = max_score
            self.result_json = result_json

        def to_dict(self):
            return {
                "id": self.id,
                "original_url": self.original_url,
                "final_url": self.final_url,
                "timestamp": str(self.timestamp),
                "status_code": self.status_code,
                "score": self.score,
                "max_score": self.max_score,
                "scan_data": json.loads(self.result_json) if self.result_json else {}
            }
