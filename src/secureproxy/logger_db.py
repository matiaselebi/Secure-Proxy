"""Logging estructurado de cada request que pasa por el proxy, en SQLite."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class LoggerDB:
    """Wrapper simple y thread-safe sobre SQLite para loguear tráfico del proxy."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False porque el proxy es multi-thread y compartimos
        # una sola instancia de LoggerDB entre requests.
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT,
                    method TEXT,
                    host TEXT,
                    port INTEGER,
                    path TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    duration_ms REAL
                )
                """
            )
            conn.commit()

    def log_request(
        self,
        client_ip: str,
        method: str,
        host: str,
        port: int,
        path: str,
        blocked: bool,
        reason: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO requests
                    (timestamp, client_ip, method, host, port, path, blocked, reason, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, method, host, port, path, int(blocked), reason, duration_ms),
            )
            conn.commit()

    def recent_blocked(self, limit: int = 20) -> list[tuple]:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                SELECT timestamp, host, reason FROM requests
                WHERE blocked = 1
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cur.fetchall()

    def stats(self) -> dict:
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE blocked = 1"
            ).fetchone()[0]
        return {"total_requests": total, "blocked_requests": blocked}
