"""Filtro de ruido del panel: que tape la telemetría sin esconder nada.

La regla que cuidan estos tests es una sola y es la que hace que la
funcionalidad no sea peligrosa: el filtro cambia la VISTA, nunca los datos
ni las decisiones. Todo lo que se oculta sigue guardado, sigue siendo
contado por separado, y aparece igual si lo buscás.
"""

import sys
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.config_writer import set_value  # noqa: E402
from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_dashboard_server  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
)
from secureproxy.view_prefs import PreferenciasDeVista  # noqa: E402

ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))

RUIDOSOS = "windowsupdate.com\ngoogle-analytics.com\nc.pki.goog\n"


def pedir(url):
    with ABRIDOR.open(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


@pytest.fixture()
def vista(tmp_path):
    (tmp_path / "ruido.txt").write_text(RUIDOSOS, encoding="utf-8")
    return PreferenciasDeVista(Blocklist(str(tmp_path / "ruido.txt")), ocultar_ruido=True)


@pytest.fixture()
def base(tmp_path, vista):
    """Historial parecido al real: mucho ruido, poca cosa interesante."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(50):
        db.log_request("127.0.0.1", "CONNECT", "www.google-analytics.com", 443, "/", True,
                       reason="dominio en blocklist: www.google-analytics.com")
    for _ in range(30):
        db.log_request("127.0.0.1", "CONNECT", "download.windowsupdate.com", 443, "/", False,
                       dest_ip="8.8.8.8", country="US", provider="Microsoft")
    for _ in range(20):
        db.log_request("127.0.0.1", "CONNECT", "c.pki.goog", 443, "/", False,
                       dest_ip="8.8.8.8", country="US", provider="Google")
    db.log_request("127.0.0.1", "CONNECT", "malicioso.test", 443, "/", True,
                   reason="dominio en blocklist: malicioso.test",
                   dest_ip="1.2.3.4", country="RU", provider="Hosting Turbio")
    db.log_request("127.0.0.1", "CONNECT", "nanopool.org", 443, "/", True,
                   reason="pool de minería de criptomonedas (posible cryptojacking)")
    # El proxy marca cada conexión al registrarla; acá se insertaron sin
    # marca a propósito, para probar de paso que el remarcado arregla una
    # base que ya existía.
    db.remarcar_ruido(vista.es_ruidoso)
    return db


# ---------------- la lista y el matcheo ----------------


def test_tapa_el_dominio_y_sus_subdominios(vista):
    assert vista.es_ruidoso("windowsupdate.com") is True
    assert vista.es_ruidoso("download.windowsupdate.com") is True
    assert vista.es_ruidoso("malicioso.test") is False


def test_apagado_no_oculta_nada(base, tmp_path):
    """Con el filtro apagado, las consultas salen enteras aunque las filas
    estén marcadas."""
    assert base.stats(ocultar=False)["total_requests"] == 102
    assert base.stats(ocultar=False)["ocultas"] == 0


def test_sin_lista_no_rompe_nada():
    """Si falta data/noisy_domains.txt, el panel tiene que andar igual."""
    sola = PreferenciasDeVista(None, ocultar_ruido=True)

    assert sola.es_ruidoso("lo.que.sea") is False
    assert sola.cantidad_de_dominios == 0


# ---------------- las consultas ----------------


def test_el_top_de_destinos_deja_de_ser_puro_ruido(base, vista):
    sin_filtro = dict(base.top_hosts(limit=10))
    con_filtro = dict(base.top_hosts(limit=10, ocultar=True))

    # sin filtro, los tres primeros puestos son telemetria y el dominio
    # malicioso ni se ve arriba
    assert "www.google-analytics.com" in sin_filtro
    assert "download.windowsupdate.com" in sin_filtro
    # con filtro, quedan solo los que importan
    assert set(con_filtro) == {"malicioso.test", "nanopool.org"}


def test_el_filtro_se_aplica_en_sql_y_no_recorta_el_top(base, vista):
    """Si se filtrara despues de traer el Top 10, los dominios ruidosos igual
    se comerian los primeros puestos y quedaria una lista de dos elementos
    donde tendria que haber diez."""
    top = base.top_hosts(limit=2, ocultar=True)

    assert len(top) == 2
    assert all(host not in RUIDOSOS for host, _ in top)


def test_los_motivos_de_bloqueo_dejan_de_estar_dominados_por_la_telemetria(base, vista):
    motivos = dict(base.bloqueos_por_motivo(limit=10, ocultar=True))

    assert not any("google-analytics" in m for m in motivos)
    assert any("malicioso.test" in m for m in motivos)


def test_los_totales_informan_cuantas_conexiones_se_ocultaron(base, vista):
    completo = base.stats()
    filtrado = base.stats(ocultar=True)

    assert completo["total_requests"] == 102
    assert filtrado["total_requests"] == 2
    # el numero que falta no se pierde: se informa aparte, para que el panel
    # pueda decirlo en pantalla
    assert filtrado["ocultas"] == 100
    assert filtrado["total_requests"] + filtrado["ocultas"] == completo["total_requests"]


def test_el_historial_no_se_llena_de_la_misma_linea(base, vista):
    filas = base.buscar(solo_bloqueadas=True, limit=25, ocultar=True)

    assert [f["host"] for f in filas] == ["nanopool.org", "malicioso.test"]


def test_buscar_un_dominio_ruidoso_igual_lo_encuentra(base, vista):
    """A proposito: si lo estas auditando, lo queres ver entero."""
    filas = base.buscar(texto="windowsupdate", limit=50, ocultar=True)

    assert len(filas) == 30


def test_nada_de_esto_borra_datos(base, vista):
    """El filtro es de vista: la base sigue teniendo todo."""
    base.buscar(solo_bloqueadas=False, limit=25, ocultar=True)

    assert base.stats()["total_requests"] == 102


def test_los_paises_tambien_se_filtran(base, vista):
    paises = dict(base.top_paises(limit=10, ocultar=True))

    # los 50 US eran de Microsoft y Google, ruido puro
    assert paises == {"RU": 1}


# ---------------- el grafico por hora ----------------


def test_el_grafico_toma_las_ultimas_24_horas_reales_no_las_ultimas_24_franjas(tmp_path):
    """El bug: se pedian 'las ultimas 24 franjas que existan', asi que si la
    PC estuvo apagada dos dias venian de dias distintos y, como el grafico
    muestra solo la hora, se veian horas repetidas y desordenadas."""
    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    for horas_atras in (1, 25, 49):
        momento = (ahora - timedelta(hours=horas_atras)).isoformat()
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO requests (timestamp, client_ip, method, host, port, path, "
                "blocked, reason, duration_ms) VALUES (?,?,?,?,?,?,?,?,?)",
                (momento, "127.0.0.1", "GET", "x.test", 80, "/", 0, "", 1.0),
            )
            conn.commit()

    franjas = db.por_hora(horas=24)

    # solo la de hace 1 hora entra en la ventana
    assert len(franjas) == 1


def test_el_grafico_sale_ordenado_de_lo_mas_viejo_a_lo_mas_nuevo(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    for horas_atras in (1, 3, 5):
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO requests (timestamp, client_ip, method, host, port, path, "
                "blocked, reason, duration_ms) VALUES (?,?,?,?,?,?,?,?,?)",
                ((ahora - timedelta(hours=horas_atras)).isoformat(),
                 "127.0.0.1", "GET", "x.test", 80, "/", 0, "", 1.0),
            )
            conn.commit()

    claves = [h for h, _t, _b in db.por_hora(horas=24)]

    assert claves == sorted(claves)
    assert len(set(claves)) == len(claves)  # ninguna hora repetida


# ---------------- el panel ----------------


def _panel(tmp_path, logger, vista, monkeypatch=None):
    (tmp_path / "bl.txt").write_text("malicioso.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, vista=vista,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_el_panel_dice_cuantas_conexiones_esta_ocultando(base, vista, tmp_path):
    """Un panel de seguridad que esconde cosas sin decirlo es peor que uno
    saturado: el numero tiene que estar a la vista."""
    server = _panel(tmp_path, base, vista)
    try:
        _status, body = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    assert "Filtro de ruido" in body
    assert "100" in body
    assert "malicioso.test" in body
    # y la telemetria no aparece en el historial
    historial = body.split('id="historial"')[1].split("</tbody>")[0]
    assert "google-analytics" not in historial


def test_con_el_filtro_apagado_el_panel_muestra_todo(base, tmp_path):
    apagada = PreferenciasDeVista(None, ocultar_ruido=False)
    server = _panel(tmp_path, base, apagada)
    try:
        _status, body = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    assert "Filtro de ruido" not in body
    historial = body.split('id="historial"')[1].split("</tbody>")[0]
    assert "google-analytics" in historial


def test_el_boton_se_aplica_en_caliente_y_queda_escrito(base, vista, tmp_path, monkeypatch):
    """Como el resto de las opciones: se escribe en el YAML y se aplica sin
    reiniciar."""
    import secureproxy.config_loader as cl

    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "config.yaml").write_text(
        "dashboard:\n  hide_noise: true\n", encoding="utf-8"
    )
    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)

    server = _panel(tmp_path, base, vista)
    try:
        pedir(f"http://127.0.0.1:{server.server_address[1]}/config?k=hide_noise&v=0")
    finally:
        server.shutdown()

    assert vista.ocultar_ruido is False
    escrito = (tmp_path / "config" / "config.yaml").read_text(encoding="utf-8")
    assert "hide_noise: false" in escrito


def test_la_exportacion_respeta_lo_que_se_ve(base, vista, tmp_path):
    """Promesa del boton Exportar: lo que ves es lo que exportas."""
    server = _panel(tmp_path, base, vista)
    try:
        _status, csv_texto = pedir(
            f"http://127.0.0.1:{server.server_address[1]}/export.csv"
        )
    finally:
        server.shutdown()

    assert "malicioso.test" in csv_texto
    assert "google-analytics" not in csv_texto


def test_el_filtro_no_toca_la_decision_de_bloquear(tmp_path, vista):
    """Lo mas importante de todo: esto es un filtro de VISTA."""
    (tmp_path / "bl.txt").write_text("windowsupdate.com\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )

    # esta en la lista de ruido Y en la blocklist: se sigue bloqueando igual
    assert engine.evaluate("windowsupdate.com").blocked is True


def test_el_acordeon_cierra_el_detalle_anterior(base, vista, tmp_path):
    """Dos detalles abiertos estiran la tabla y obligan a scrollear justo
    cuando queres comparar dos conexiones parecidas."""
    server = _panel(tmp_path, base, vista)
    try:
        _status, body = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    js = body.split("function verDetalle")[1].split("}")[0:8]
    js = "}".join(js)
    assert "querySelectorAll('.detalle-fila.abierta')" in js
    assert "remove('abierta')" in js


def test_config_writer_puede_escribir_la_seccion_nueva(tmp_path):
    yaml = tmp_path / "c.yaml"
    yaml.write_text(
        "# comentario que no se tiene que perder\ndashboard:\n  hide_noise: true\n",
        encoding="utf-8",
    )

    set_value(yaml, "dashboard", "hide_noise", False)

    texto = yaml.read_text(encoding="utf-8")
    assert "hide_noise: false" in texto
    assert "comentario que no se tiene que perder" in texto


def test_el_remarcado_arregla_una_base_que_ya_existia(tmp_path, vista):
    """Una base creada antes de que existiera el filtro tiene todas las filas
    sin marcar. Al arrancar se remarcan, y el panel queda consistente desde el
    primer refresco en vez de esperar a que pase tráfico nuevo."""
    db = LoggerDB(str(tmp_path / "vieja.db"))
    for _ in range(5):
        db.log_request("127.0.0.1", "GET", "download.windowsupdate.com", 80, "/", False)
    db.log_request("127.0.0.1", "GET", "malicioso.test", 80, "/", True)

    assert db.stats(ocultar=True)["ocultas"] == 0  # todavía sin marcar
    cambios = db.remarcar_ruido(vista.es_ruidoso)

    assert cambios == 5
    assert db.stats(ocultar=True)["ocultas"] == 5


def test_el_remarcado_tambien_desmarca_si_sacaste_un_dominio_de_la_lista(tmp_path, vista):
    """Editar data/noisy_domains.txt a mano tiene que poder deshacerse."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(3):
        db.log_request("127.0.0.1", "GET", "c.pki.goog", 80, "/", False, noisy=True)
    assert db.stats(ocultar=True)["ocultas"] == 3

    cambios = db.remarcar_ruido(lambda host: False)  # lista vacía

    assert cambios == 3
    assert db.stats(ocultar=True)["ocultas"] == 0


def test_el_filtro_no_se_arrastra_con_un_historial_grande(tmp_path, vista):
    """La razón por la que la marca es una columna y no una comparación por
    consulta: con LIKE contra los ~50 dominios de la lista, un refresco del
    panel sobre 200.000 filas tardaba 3 segundos."""
    import time

    db = LoggerDB(str(tmp_path / "grande.db"), max_rows=0)
    ruidosos = ["download.windowsupdate.com", "c.pki.goog", "www.google-analytics.com"]
    with db._connect() as conn:
        filas = []
        for i in range(60_000):
            host = ruidosos[i % 3] if i % 2 else f"sitio{i % 300}.com"
            filas.append((
                "2026-08-01T12:00:00+00:00", "127.0.0.1", "CONNECT", host, 443, "/",
                i % 20 == 0, "motivo", 1.0, "8.8.8.8", "US", "AS1", "P", int(bool(i % 2)),
            ))
        conn.executemany(
            "INSERT INTO requests (timestamp, client_ip, method, host, port, path, blocked, "
            "reason, duration_ms, dest_ip, country, asn, provider, noisy) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", filas)
        conn.commit()

    inicio = time.time()
    db.stats(ocultar=True)
    db.buscar(solo_bloqueadas=True, limit=50, ocultar=True)
    db.top_hosts(limit=10, ocultar=True)
    db.top_paises(limit=10, ocultar=True)
    db.bloqueos_por_motivo(limit=10, ocultar=True)
    tardo = time.time() - inicio

    assert tardo < 1.0, f"un refresco del panel tardó {tardo:.2f}s"
