"""Tests de la pestaña Configuracion del dashboard.

Lo que se garantiza aca:
- los cambios se PERSISTEN en config.yaml sin destruir los comentarios,
- se aplican EN CALIENTE al motor que ya esta corriendo,
- valores invalidos o claves no listadas no cambian nada (una URL no puede
  escribir cualquier cosa en el archivo de configuracion).
"""

import shutil
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

import secureproxy.config_loader as cl  # noqa: E402
from secureproxy.config_writer import read_value, set_value  # noqa: E402


@pytest.fixture
def config_temporal(tmp_path):
    destino = tmp_path / "config.yaml"
    shutil.copy(RAIZ / "config" / "config.yaml", destino)
    return destino


def test_escribir_no_borra_comentarios(config_temporal):
    original = config_temporal.read_text(encoding="utf-8")
    assert set_value(config_temporal, "filtering", "mode", "audit")
    nuevo = config_temporal.read_text(encoding="utf-8")

    comentarios_antes = [l for l in original.splitlines() if l.strip().startswith("#")]
    comentarios_despues = [l for l in nuevo.splitlines() if l.strip().startswith("#")]
    assert comentarios_antes == comentarios_despues
    assert len(original.splitlines()) == len(nuevo.splitlines())
    assert read_value(config_temporal, "filtering", "mode") == "audit"


def test_escribir_tipos_distintos(config_temporal):
    set_value(config_temporal, "filtering", "abuseipdb_min_score", 25)
    set_value(config_temporal, "filtering", "check_tor_exit_nodes", False)
    set_value(config_temporal, "firewall", "enabled", True)
    assert read_value(config_temporal, "filtering", "abuseipdb_min_score") == 25
    assert read_value(config_temporal, "filtering", "check_tor_exit_nodes") is False
    assert read_value(config_temporal, "firewall", "enabled") is True


def test_no_crea_claves_inventadas(config_temporal):
    assert set_value(config_temporal, "filtering", "clave_que_no_existe", 1) is False
    assert "clave_que_no_existe" not in config_temporal.read_text(encoding="utf-8")


def test_no_confunde_claves_de_secciones_distintas(config_temporal):
    """'enabled' existe en la seccion firewall y en telegram: cambiar una no
    debe tocar la otra."""
    set_value(config_temporal, "firewall", "enabled", True)
    assert read_value(config_temporal, "firewall", "enabled") is True
    assert read_value(config_temporal, "telegram", "enabled") is False


# ---------- el panel end-to-end ----------

def _dashboard(tmp_path, monkeypatch):
    from secureproxy.filter_engine import FilterEngine
    from secureproxy.firewall_rules import FirewallManager
    from secureproxy.logger_db import LoggerDB
    from secureproxy.notifier import TelegramNotifier
    from secureproxy.proxy_server import build_dashboard_server
    from secureproxy.threat_intel import (
        AbuseIPDBClient, Allowlist, Blocklist, TorExitNodeList,
    )

    (tmp_path / "config").mkdir(exist_ok=True)
    shutil.copy(RAIZ / "config" / "config.yaml", tmp_path / "config" / "config.yaml")
    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)

    for nombre in ("b.txt", "a.txt"):
        (tmp_path / nombre).write_text("")
    allowlist = Allowlist(str(tmp_path / "a.txt"))
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "b.txt")),
        abuseipdb_client=AbuseIPDBClient(""),
        tor_list=TorExitNodeList(),
        allowlist=allowlist,
        abuseipdb_min_score=50,
        check_tor_exit_nodes=True,
        mode="enforce",
    )
    firewall = FirewallManager(False)
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), firewall, allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return base, engine, firewall, server, tmp_path / "config" / "config.yaml"


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def test_cambiar_modo_se_aplica_en_caliente_y_se_guarda(tmp_path, monkeypatch):
    base, engine, _fw, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=mode&v=audit")
        assert engine.mode == "audit"                      # en caliente
        assert read_value(cfg, "filtering", "mode") == "audit"  # y persistido
        _get(f"{base}/config?k=mode&v=enforce")
        assert engine.mode == "enforce"
    finally:
        server.shutdown()


def test_cambiar_score_y_tor_en_caliente(tmp_path, monkeypatch):
    base, engine, _fw, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=abuseipdb_min_score&v=25")
        assert engine.abuseipdb_min_score == 25
        assert read_value(cfg, "filtering", "abuseipdb_min_score") == 25

        _get(f"{base}/config?k=check_tor_exit_nodes&v=0")
        assert engine.check_tor_exit_nodes is False
    finally:
        server.shutdown()


def test_firewall_real_se_puede_prender_desde_el_panel(tmp_path, monkeypatch):
    base, _engine, firewall, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=firewall_enabled&v=1")
        assert firewall.enabled is True
        assert read_value(cfg, "firewall", "enabled") is True
    finally:
        server.shutdown()


def test_valores_invalidos_no_cambian_nada(tmp_path, monkeypatch):
    base, engine, _fw, server, _cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=mode&v=modo_inventado")
        assert engine.mode == "enforce"

        _get(f"{base}/config?k=abuseipdb_min_score&v=999")   # fuera de rango
        _get(f"{base}/config?k=abuseipdb_min_score&v=hola")  # no es numero
        assert engine.abuseipdb_min_score == 50

        _get(f"{base}/config?k=clave_no_listada&v=1")        # no esta en la lista blanca
        assert engine.mode == "enforce"
    finally:
        server.shutdown()


def test_el_panel_se_renderiza_con_el_estado_actual(tmp_path, monkeypatch):
    base, engine, _fw, server, _cfg = _dashboard(tmp_path, monkeypatch)
    try:
        engine.mode = "audit"
        body = _get(f"{base}/")
        assert "Configuración" in body
        assert "tab-config" in body
        # La tarjeta activa se marca con un badge, no con texto pegado al boton.
        assert "en uso" in body
        # y la que NO esta activa ofrece cambiarse, con confirmacion previa
        assert "Cambiar a este modo" in body
        assert "confirm(" in body
    finally:
        server.shutdown()
