"""Fase 3: quién se conectó, cuánto movió, con qué ritmo, y avisar.

Las cuatro cosas comparten una regla: son CONTEXTO, no decisión. Ninguna
cambia qué se bloquea, y si alguna falla la conexión se registra igual. Los
tests cuidan las dos puntas: que el dato sea cierto, y que no poder
obtenerlo nunca rompa el camino del tráfico.
"""

import os
import socket
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.desktop_alerts import DesktopNotifier  # noqa: E402
from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.process_lookup import ProcessLookup  # noqa: E402
from secureproxy.proxy_server import (  # noqa: E402
    build_dashboard_server,
    build_proxy_server,
    formatear_bytes,
)
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
)

ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def pedir(url):
    with ABRIDOR.open(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


# ---------------- 1. quién se conectó ----------------


def test_se_identifica_el_proceso_que_abrio_la_conexion():
    """El dato que le faltaba al proyecto: cuando salta "buscá qué proceso se
    conectó", poder decir cuál fue."""
    lookup = ProcessLookup(True)
    if not lookup.disponible:
        pytest.skip("este sistema no expone la tabla de sockets")

    servidor = socket.socket()
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(5)
    visto = []

    def atender():
        conexion, direccion = servidor.accept()
        visto.append(lookup.nombre_de_puerto(direccion[1]))
        conexion.close()

    threading.Thread(target=atender, daemon=True).start()
    time.sleep(0.2)
    cliente = socket.create_connection(servidor.getsockname(), timeout=5)
    time.sleep(0.4)
    cliente.close()
    servidor.close()
    time.sleep(0.2)

    assert visto, "no se atendió la conexión"
    # El que se conectó somos nosotros mismos, así que lo que tiene que
    # coincidir es NUESTRO PID.
    #
    # Antes acá se pedía que el nombre contuviera "python", y eso no prueba lo
    # que parece: prueba cómo se lanzó pytest. Corriendo `python -m pytest` el
    # ejecutable se llama "python3" y pasaba; corriendo el comando `pytest` a
    # secas -que es lo que hace el CI- se llama "pytest" y fallaba, con la
    # búsqueda funcionando perfectamente. El PID no depende de nada de eso.
    assert f"(PID {os.getpid()})" in visto[0], visto[0]


def test_un_puerto_que_no_existe_no_inventa_nada():
    lookup = ProcessLookup(True)

    assert lookup.nombre_de_puerto(0) == ""
    assert lookup.nombre_de_puerto(65000) in ("", )  # o vacío, o nada


def test_desactivado_no_consulta_nada():
    lookup = ProcessLookup(False)

    assert lookup.disponible is False
    assert lookup.nombre_de_puerto(1234) == ""


def test_no_se_arrastra_cuando_ningun_puerto_se_resuelve():
    """El freno: sin él, cada conexión sin resolver relee la tabla entera.
    Con él, 5.000 consultas fallidas no cuestan casi nada."""
    lookup = ProcessLookup(True)
    if not lookup.disponible:
        pytest.skip("este sistema no expone la tabla de sockets")
    lookup.nombre_de_puerto(1)

    inicio = time.time()
    for i in range(5000):
        lookup.nombre_de_puerto(40000 + i)
    tardo = time.time() - inicio

    assert tardo < 1.0, f"5000 consultas fallidas tardaron {tardo:.2f}s"


def test_el_freno_no_se_activa_cuando_los_puertos_si_se_resuelven():
    """El primer intento tenía un freno de tiempo fijo y rompía las ráfagas:
    un navegador abriendo diez conexiones de golpe resolvía la primera y
    perdía las otras nueve."""
    lookup = ProcessLookup(True)
    if not lookup.disponible:
        pytest.skip("este sistema no expone la tabla de sockets")

    servidor = socket.socket()
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(20)
    vistos = []

    def atender():
        for _ in range(6):
            conexion, direccion = servidor.accept()
            vistos.append(lookup.nombre_de_puerto(direccion[1]))
            conexion.close()

    threading.Thread(target=atender, daemon=True).start()
    time.sleep(0.2)
    # ráfaga, todas juntas y sin pausa entre medio
    clientes = [socket.create_connection(servidor.getsockname(), timeout=5) for _ in range(6)]
    time.sleep(1.0)
    for c in clientes:
        c.close()
    servidor.close()

    resueltos = [v for v in vistos if v]
    assert len(resueltos) >= 5, f"solo se resolvieron {len(resueltos)} de {len(vistos)}"


# ---------------- 2. volumen ----------------


class _Backend(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A002
        pass

    def do_GET(self):
        cuerpo = b"x" * 5000
        self.send_response(200)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_POST(self):
        largo = int(self.headers.get("Content-Length", 0))
        self.rfile.read(largo)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def escenario(tmp_path):
    backend = HTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    (tmp_path / "bl.txt").write_text("bloqueado.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
        # El backend de prueba está en 127.0.0.1 y en un puerto efímero.
        allow_internal_destinations=True,
    )
    logger = LoggerDB(str(tmp_path / "l.db"))
    proxy = build_proxy_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, procesos=ProcessLookup(True),
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield {
            "backend": backend.server_address[1],
            "proxy": proxy.server_address[1],
            "logger": logger,
            "engine": engine,
        }
    finally:
        proxy.shutdown()
        backend.shutdown()


def _esperar_fila(logger, predicado, espera=5.0):
    limite = time.time() + espera
    while time.time() < limite:
        for fila in logger.buscar(solo_bloqueadas=False, limit=20):
            if predicado(fila):
                return fila
        time.sleep(0.05)
    raise AssertionError("no apareció la fila esperada")


def test_se_cuenta_lo_que_baja_en_un_get(escenario):
    requests.get(
        f"http://127.0.0.1:{escenario['backend']}/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy']}"}, timeout=10,
    )

    fila = _esperar_fila(escenario["logger"], lambda f: f["bytes_in"] == 5000)
    assert fila["bytes_out"] == 0


def test_se_cuenta_lo_que_sube_en_un_post(escenario):
    requests.post(
        f"http://127.0.0.1:{escenario['backend']}/", data=b"A" * 3000,
        proxies={"http": f"http://127.0.0.1:{escenario['proxy']}"}, timeout=10,
    )

    fila = _esperar_fila(escenario["logger"], lambda f: f["bytes_out"] == 3000)
    assert fila["method"] == "POST"


def test_se_cuenta_el_volumen_del_tunel_https(escenario):
    """Es la única forma de medir volumen en HTTPS: el contenido va cifrado,
    pero cuánto se movió y para qué lado se ve igual."""
    sock = socket.create_connection(("127.0.0.1", escenario["proxy"]), timeout=10)
    destino = f"127.0.0.1:{escenario['backend']}"
    sock.sendall(f"CONNECT {destino} HTTP/1.1\r\nHost: {destino}\r\n\r\n".encode())
    sock.recv(128)
    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    while sock.recv(65536):
        pass
    sock.close()

    fila = _esperar_fila(escenario["logger"], lambda f: f["method"] == "CONNECT")
    assert fila["bytes_out"] > 0, "no se contó lo subido por el túnel"
    assert fila["bytes_in"] > 5000, "no se contó lo bajado por el túnel"


def test_el_proceso_queda_registrado_en_el_trafico_real(escenario):
    lookup = ProcessLookup(True)
    if not lookup.disponible:
        pytest.skip("este sistema no expone la tabla de sockets")

    requests.get(
        f"http://127.0.0.1:{escenario['backend']}/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy']}"}, timeout=10,
    )

    fila = _esperar_fila(escenario["logger"], lambda f: bool(f["process"]))
    # Quien abrió la conexión hacia el proxy es este mismo proceso de tests,
    # así que el PID registrado tiene que ser el nuestro. Se compara por PID y
    # no por nombre: el nombre depende de cómo se haya lanzado pytest, no del
    # proxy (ver el comentario en test_se_identifica_el_proceso_que_abrio_la_conexion).
    assert f"(PID {os.getpid()})" in fila["process"], fila["process"]


def test_el_proceso_se_resuelve_aunque_la_conexion_se_bloquee(escenario):
    """Es justo el caso donde más se necesita: saber quién intentó."""
    lookup = ProcessLookup(True)
    if not lookup.disponible:
        pytest.skip("este sistema no expone la tabla de sockets")

    requests.get(
        "http://bloqueado.test/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy']}"}, timeout=10,
    )

    fila = _esperar_fila(
        escenario["logger"], lambda f: f["host"] == "bloqueado.test"
    )
    assert fila["process"], "el bloqueo no registró el proceso"


def test_sin_identificacion_de_procesos_el_trafico_sigue_andando(tmp_path):
    """Es contexto: que no se pueda averiguar nunca puede cortar nada."""
    backend = HTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
        # El backend de prueba está en 127.0.0.1 y en un puerto efímero.
        allow_internal_destinations=True,
    )
    logger = LoggerDB(str(tmp_path / "l.db"))
    proxy = build_proxy_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, procesos=ProcessLookup(False),
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        respuesta = requests.get(
            f"http://127.0.0.1:{backend.server_address[1]}/",
            proxies={"http": f"http://127.0.0.1:{proxy.server_address[1]}"}, timeout=10,
        )
        assert respuesta.status_code == 200
        fila = _esperar_fila(logger, lambda f: f["method"] == "GET")
        assert fila["process"] in ("", None)
    finally:
        proxy.shutdown()
        backend.shutdown()


def test_formatear_bytes_se_lee():
    assert formatear_bytes(0) == "0 B"
    assert formatear_bytes(900) == "900 B"
    assert formatear_bytes(1024 * 1024 * 1.4).endswith("MB")
    assert formatear_bytes(None) == "0 B"


# ---------------- 3. beaconing ----------------


def _sembrar(db, host, momentos, proceso=""):
    with db._connect() as conn:
        for momento in momentos:
            conn.execute(
                "INSERT INTO requests (timestamp, client_ip, method, host, port, path, "
                "blocked, reason, duration_ms, process, noisy, bytes_out, bytes_in) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,0,0,0)",
                (momento.isoformat(), "127.0.0.1", "CONNECT", host, 443, "/", 0, "",
                 1.0, proceso),
            )
        conn.commit()


@pytest.fixture()
def historial(tmp_path):
    import random

    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    rnd = random.Random(3)

    # un implante perfecto: cada 60 segundos, clavado
    _sembrar(db, "c2-perfecto.test",
             [ahora - timedelta(seconds=60 * i) for i in range(40)],
             "rundll32.exe (PID 99)")
    # uno con jitter del 8%, que sigue siendo regularísimo para un humano
    _sembrar(db, "c2-con-jitter.test",
             [ahora - timedelta(seconds=300 * i + rnd.uniform(-25, 25)) for i in range(20)],
             "svchost.exe (PID 4)")
    # navegación: intervalos caóticos
    _sembrar(db, "noticias.test",
             [ahora - timedelta(seconds=sum(rnd.uniform(2, 900) for _ in range(i + 1)))
              for i in range(30)], "chrome.exe (PID 7)")
    # streaming: muchísimas conexiones muy juntas
    _sembrar(db, "video.test",
             [ahora - timedelta(seconds=0.7 * i) for i in range(900)], "chrome.exe (PID 7)")
    return db


def test_encuentra_el_ritmo_de_reloj(historial):
    hallados = {f["destino"]: f for f in historial.beaconing(horas=24)}

    assert "c2-perfecto.test" in hallados
    assert "c2-con-jitter.test" in hallados


def test_no_confunde_navegacion_humana_con_un_implante(historial):
    hallados = {f["destino"] for f in historial.beaconing(horas=24)}

    assert "noticias.test" not in hallados


def test_no_confunde_streaming_con_un_implante(historial):
    """Muchas conexiones muy juntas es volumen, y para eso está el otro
    detector: acá se descarta por intervalo demasiado corto."""
    hallados = {f["destino"] for f in historial.beaconing(horas=24)}

    assert "video.test" not in hallados


def test_informa_el_intervalo_el_jitter_y_el_proceso(historial):
    fila = next(f for f in historial.beaconing(horas=24)
                if f["destino"] == "c2-perfecto.test")

    assert fila["conexiones"] == 40
    assert 59 < fila["promedio"] < 61
    assert fila["coeficiente"] < 0.01
    assert fila["proceso"] == "rundll32.exe (PID 99)"
    # Y el motivo, que es lo que hace entendible la pantalla.
    assert "conexiones cada" in fila["motivo"]


def test_lo_mas_regular_va_primero(historial):
    resultados = historial.beaconing(horas=24)

    jitters = [f["coeficiente"] for f in resultados]
    assert jitters == sorted(jitters)


def test_hacen_falta_suficientes_muestras(tmp_path):
    """Con tres conexiones, cualquier cosa parece regular."""
    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    _sembrar(db, "pocas.test", [ahora - timedelta(seconds=60 * i) for i in range(4)])

    assert db.beaconing(horas=24, minimo=8) == []


def test_el_beaconing_respeta_el_filtro_de_ruido(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    _sembrar(db, "telemetria.test", [ahora - timedelta(seconds=60 * i) for i in range(30)])
    with db._connect() as conn:
        conn.execute("UPDATE requests SET noisy = 1")
        conn.commit()

    assert db.beaconing(horas=24, ocultar=True) == []
    assert db.beaconing(horas=24, ocultar=False) != []


# ---------------- volumen agregado ----------------


def test_el_top_por_volumen_ordena_por_lo_subido(tmp_path):
    """Lo subido y no lo bajado: bajar mucho es ver un video."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_request("127.0.0.1", "CONNECT", "video.test", 443, "/", False,
                   bytes_out=1000, bytes_in=900_000_000)
    db.log_request("127.0.0.1", "CONNECT", "sospechoso.test", 443, "/", False,
                   bytes_out=800_000_000, bytes_in=2000, process="raro.exe (PID 5)")

    top = db.top_por_volumen(limit=10)

    assert top[0][0] == "sospechoso.test"
    assert top[0][3] == "raro.exe (PID 5)"


# ---------------- 4. avisos ----------------


def test_solo_avisa_de_lo_que_significa_algo():
    avisos = DesktopNotifier(True, solo_graves=True)

    assert avisos.merece_aviso("IP 1.2.3.4 es un servidor de C2 conocido (Feodo Tracker)")
    assert avisos.merece_aviso("pool de minería de criptomonedas (posible cryptojacking): x")
    assert avisos.merece_aviso("IP 5.6.7.8 con score de abuso 90 (AbuseIPDB)")
    assert avisos.merece_aviso("IP 9.9.9.9 está en un rango de mala reputación (FireHOL)")
    assert avisos.merece_aviso("IP 1.1.1.1 es un nodo de salida TOR conocido")
    # de la lista manual ya sabés: no interrumpe
    assert not avisos.merece_aviso("dominio en blocklist: www.google-analytics.com")


def test_las_claves_son_frases_para_no_avisar_de_mas():
    """Con "tor" a secas, bloquear torproject.org desde la lista manual
    dispararía un aviso de "nodo TOR" que no es cierto."""
    avisos = DesktopNotifier(True, solo_graves=True)

    assert not avisos.merece_aviso("dominio en blocklist: torproject.org")
    assert not avisos.merece_aviso("dominio en blocklist: c2000.com")


def test_con_solo_graves_apagado_avisa_de_todo():
    avisos = DesktopNotifier(True, solo_graves=False)

    assert avisos.merece_aviso("dominio en blocklist: cualquiera.com")


def test_el_mismo_dominio_no_avisa_doscientas_veces():
    avisos = DesktopNotifier(True, True)
    avisos._soportado = True

    primero = avisos.avisar_bloqueo("malo.test", "servidor de c2")
    repetidos = [avisos.avisar_bloqueo("malo.test", "servidor de c2") for _ in range(50)]

    assert primero is True
    assert not any(repetidos)


def test_hay_un_techo_por_hora():
    """Si algo sale muy mal, preferimos perder avisos antes que tapar la
    pantalla: una herramienta que molesta termina apagada."""
    avisos = DesktopNotifier(True, True)
    avisos._soportado = True

    mandados = [avisos.avisar_bloqueo(f"d{i}.test", "servidor de c2") for i in range(40)]

    assert sum(mandados) == 12


def test_apagar_y_prender_no_las_deja_rotas():
    avisos = DesktopNotifier(True, True)
    avisos._soportado = True
    assert avisos.disponible is True

    avisos.enabled = False
    assert avisos.disponible is False

    avisos.enabled = True
    assert avisos.disponible is True


def test_desactivadas_no_mandan_nada():
    avisos = DesktopNotifier(False, True)

    assert avisos.disponible is False
    assert avisos.avisar_bloqueo("malo.test", "servidor de c2") is False


def test_un_sistema_sin_notificaciones_no_rompe_nada():
    avisos = DesktopNotifier(True, True)
    avisos._soportado = False

    assert avisos.disponible is False
    assert avisos.avisar_bloqueo("malo.test", "servidor de c2") is False
    assert avisos.estado()["ok"] is False


# ---------------- el panel ----------------


@pytest.fixture()
def panel(tmp_path):
    import random

    (tmp_path / "bl.txt").write_text("malo.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    logger = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc)
    rnd = random.Random(1)
    _sembrar(logger, "c2-perfecto.test",
             [ahora - timedelta(seconds=60 * i) for i in range(30)],
             "rundll32.exe (PID 99)")
    _sembrar(logger, "ruidoso.test",
             [ahora - timedelta(seconds=rnd.uniform(0, 3600)) for i in range(5)],
             "chrome.exe (PID 7)")
    logger.log_request("127.0.0.1", "CONNECT", "subida.test", 443, "/", False,
                       bytes_out=900_000_000, bytes_in=100,
                       process="raro.exe (PID 55)")
    servidor = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
        alertas=DesktopNotifier(True, True),
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{servidor.server_address[1]}", logger
    finally:
        servidor.shutdown()


def test_el_panel_muestra_el_proceso_en_el_historial(panel):
    base, _logger = panel

    _status, body = pedir(base + "/?q=c2-perfecto")

    historial = body.split('id="historial"')[1].split("</tbody>")[0]
    assert "rundll32.exe (PID 99)" in historial


def test_el_panel_muestra_el_beaconing(panel):
    base, _logger = panel

    _status, body = pedir(base + "/")

    stats = body.split('id="estadisticas"')[1]
    assert "ritmo de reloj" in stats
    assert "c2-perfecto.test" in stats
    assert "rundll32.exe (PID 99)" in stats


def test_el_panel_muestra_adonde_se_subieron_datos(panel):
    base, _logger = panel

    _status, body = pedir(base + "/")

    stats = body.split('id="estadisticas"')[1]
    assert "subiste más datos" in stats
    assert "subida.test" in stats
    assert "MB" in stats or "GB" in stats


def test_el_detalle_muestra_proceso_y_volumen(panel):
    base, _logger = panel

    _status, body = pedir(base + "/?q=subida.test")

    assert "Proceso" in body
    assert "raro.exe (PID 55)" in body
    assert "Subido" in body and "Bajado" in body


def test_el_panel_de_salud_informa_el_estado_de_los_avisos(panel):
    base, _logger = panel

    _status, body = pedir(base + "/")

    assert "Avisos en el escritorio" in body


def test_los_avisos_se_pueden_apagar_desde_el_panel(panel, tmp_path, monkeypatch):
    import secureproxy.config_loader as cl

    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "config.yaml").write_text(
        "alerts:\n  enabled: true\n", encoding="utf-8"
    )
    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)
    base, _logger = panel

    pedir(base + "/config?k=alerts_enabled&v=0")

    escrito = (tmp_path / "config" / "config.yaml").read_text(encoding="utf-8")
    assert "enabled: false" in escrito


def test_se_puede_buscar_por_proceso(panel):
    """Auditar "qué hizo este ejecutable" es la pregunta natural una vez que
    sabés qué proceso fue."""
    base, logger = panel

    filas = logger.buscar(texto="rundll32", limit=50)

    assert filas and all("rundll32" in f["process"] for f in filas)
