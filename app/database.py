"""Database configuration and session management using SQLAlchemy and SQLite."""

import os
import sqlite3

DATABASE_PATH = os.getenv("DATABASE_PATH", "./scans.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker
    HAS_SQLALCHEMY = True

    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()

except ImportError:
    HAS_SQLALCHEMY = False
    engine = None
    SessionLocal = None

    class Base:
        metadata = None
        __tablename__ = ""


def get_sqlite_conn():
    """Returns a direct standard library sqlite3 connection."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    """Dependency for yielding database sessions per request."""
    if HAS_SQLALCHEMY and SessionLocal:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
    else:
        conn = get_sqlite_conn()
        try:
            yield conn
        finally:
            conn.close()


def init_db():
    """Create all database tables."""
    if HAS_SQLALCHEMY and engine and hasattr(Base, "metadata") and Base.metadata:
        Base.metadata.create_all(bind=engine)
    else:
        conn = get_sqlite_conn()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                original_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                result_json TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (original_url);")
        conn.commit()
        conn.close()
