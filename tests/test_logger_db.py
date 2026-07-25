import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.logger_db import LoggerDB  # noqa: E402


def test_log_and_read_back(tmp_path):
    db = LoggerDB(str(tmp_path / "test.db"))

    db.log_request("127.0.0.1", "GET", "example.com", 80, "/", False)
    db.log_request(
        "127.0.0.1", "CONNECT", "malicious-example.com", 443, "-", True,
        reason="dominio en blocklist: malicious-example.com",
    )

    stats = db.stats()
    assert stats["total_requests"] == 2
    assert stats["blocked_requests"] == 1

    blocked = db.recent_blocked(limit=5)
    assert len(blocked) == 1
    assert blocked[0][1] == "malicious-example.com"
