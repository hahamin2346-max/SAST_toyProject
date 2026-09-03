import os
import sqlite3
from pathlib import Path


def default_database_path() -> Path:
    configured = os.getenv("SAST_DB_PATH")
    return Path(configured) if configured else Path(__file__).parent.parent / "data" / "sast.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    database_path = Path(path) if path else default_database_path()
    if str(database_path) != ":memory:":
        database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database_path), timeout=30, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    connection.executescript(schema)
    connection.commit()
    return connection
