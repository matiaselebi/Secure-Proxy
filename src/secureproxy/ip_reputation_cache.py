"""Cache persistente (SQLite) de reputación de IPs consultadas en AbuseIPDB.

El cache en memoria de AbuseIPDBClient se pierde cada vez que se reinicia el
proxy; este cache persiste entre reinicios, para no volver a gastar cupo de
la API (el plan gratuito da 1000 consultas/día) preguntando por una IP que
ya se consultó hace poco.
"""

import sqlite3
import threading
import time
from pathlib import Path


class PersistentIPCache:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_reputation_cache (
                    ip TEXT PRIMARY KEY,
                    score INTEGER NOT NULL,
                    checked_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def get(self, ip: str, max_age_seconds: float) -> int | None:
        """Devuelve el score cacheado si existe y no venció, o None."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT score, checked_at FROM ip_reputation_cache WHERE ip = ?", (ip,)
            ).fetchone()
        if row is None:
            return None
        score, checked_at = row
        if (time.time() - checked_at) >= max_age_seconds:
            return None
        return score

    def set(self, ip: str, score: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ip_reputation_cache (ip, score, checked_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET score = excluded.score, checked_at = excluded.checked_at
                """,
                (ip, score, time.time()),
            )
            conn.commit()

    def clear(self) -> None:
        """Borra todas las entradas cacheadas. Pensado para el botón "Borrar
        cache" del dashboard/menú .bat: la próxima vez que se consulte
        cualquier IP, se le vuelve a preguntar a la API de AbuseIPDB."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM ip_reputation_cache")
            conn.commit()

    def count(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM ip_reputation_cache").fetchone()
        return row[0] if row else 0
