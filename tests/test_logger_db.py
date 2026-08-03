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


def test_el_historial_se_recorta_solo_al_pasar_el_tope(tmp_path):
    """El proxy del sistema ve TODAS las conexiones de la PC: sin tope, el
    archivo crece para siempre. En una prueba real llego a 168 MB y 1,6
    millones de filas, y ahi el dashboard no abria mas."""
    db = LoggerDB(str(tmp_path / "logs.db"), max_rows=100)
    db.PRUNE_EVERY = 10  # para no tener que insertar 500 en el test

    for i in range(300):
        db.log_request("127.0.0.1", "GET", f"host{i}.test", 80, "/", False)

    total = db.stats()["total_requests"]
    assert total <= 110, f"quedaron {total} filas; el recorte no actuo"


def test_el_recorte_conserva_las_mas_recientes(tmp_path):
    db = LoggerDB(str(tmp_path / "logs.db"), max_rows=50)
    for i in range(200):
        db.log_request("127.0.0.1", "GET", f"host{i}.test", 80, "/", True)
    db.prune()

    recientes = db.recent_blocked(limit=5)
    hosts = [fila[1] for fila in recientes]
    assert "host199.test" in hosts, "se borro lo nuevo en vez de lo viejo"


def test_max_rows_cero_desactiva_el_recorte(tmp_path):
    db = LoggerDB(str(tmp_path / "logs.db"), max_rows=0)
    db.PRUNE_EVERY = 5
    for i in range(50):
        db.log_request("127.0.0.1", "GET", "x.test", 80, "/", False)

    assert db.stats()["total_requests"] == 50


def test_clear_vacia_el_historial(tmp_path):
    db = LoggerDB(str(tmp_path / "logs.db"))
    for _ in range(10):
        db.log_request("127.0.0.1", "GET", "x.test", 80, "/", True)

    borradas = db.clear()

    assert borradas == 10
    assert db.stats() == {"total_requests": 0, "blocked_requests": 0, "ocultas": 0}


def test_hay_indices_para_que_el_dashboard_no_se_arrastre(tmp_path):
    """Sin indice, contar bloqueadas y pedir las ultimas 25 recorre la tabla
    entera en cada refresco (cada 5 segundos)."""
    import sqlite3

    db = LoggerDB(str(tmp_path / "logs.db"))
    con = sqlite3.connect(db.db_path)
    indices = {fila[0] for fila in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='requests'"
    )}
    con.close()

    assert any("blocked" in nombre for nombre in indices)
