"""Tests del panel de salud, historial con detalle, estadisticas, exportacion
y consulta OSINT (la tanda que no toca el motor de filtrado).

Todo esto sale de datos que el proxy YA guardaba: son consultas y formato, no
un registro nuevo. Por eso ninguna de estas funciones puede cambiar lo que el
proxy bloquea o deja pasar, y los tests lo comprueban desde afuera, pidiendo
la pagina como lo haria un navegador.
"""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import feeds_status  # noqa: E402
from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import (  # noqa: E402
    build_dashboard_server,
    formatear_fecha,
    hace_cuanto,
)
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
)

# Abridor que no pasa por ningun proxy: si no, en una maquina con el proxy
# del sistema puesto, los tests saldrian por el propio proxy.
ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def pedir(url):
    with ABRIDOR.open(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)


@pytest.fixture
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("malo.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("bueno.test\n", encoding="utf-8")
    (tmp_path / "ip.txt").write_text("6.6.6.6\n", encoding="utf-8")

    logger = LoggerDB(str(tmp_path / "logs.db"))
    for i in range(12):
        bloqueada = i % 2 == 0
        logger.log_request(
            "127.0.0.1", "CONNECT", f"sitio{i % 3}.test", 443, "/", bloqueada,
            reason="dominio en blocklist" if bloqueada else "",
            duration_ms=1.5 + i,
        )

    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        ip_blocklist=IPBlocklist(str(tmp_path / "ip.txt")),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield base, logger, engine
    server.shutdown()


# ---------------- formato de fecha ----------------


def test_la_fecha_se_muestra_legible_y_en_hora_local():
    """En la base se guarda ISO en UTC porque asi se ordena bien, pero
    mostrar '2026-07-27T00:09:15.704172+00:00' en la tabla es ilegible y
    ademas no es la hora que marca tu reloj."""
    salida = formatear_fecha("2026-07-27T00:09:15.704172+00:00")

    assert "T" not in salida and "+00:00" not in salida
    assert salida.count(":") == 2 and salida.count("/") == 2


def test_una_fecha_rota_no_tumba_la_pagina():
    assert formatear_fecha("cualquier cosa") == "cualquier cosa"


def test_hace_cuanto_habla_en_castellano():
    from datetime import datetime, timedelta, timezone

    ahora = datetime.now(timezone.utc)
    assert hace_cuanto("") == "nunca"
    assert hace_cuanto((ahora - timedelta(seconds=10)).isoformat()) == "recién"
    assert hace_cuanto((ahora - timedelta(minutes=12)).isoformat()) == "hace 12 min"
    assert hace_cuanto((ahora - timedelta(hours=3)).isoformat()) == "hace 3 h"


# ---------------- panel de salud ----------------


def test_el_panel_de_salud_muestra_cada_fuente(panel):
    base, _logger, _engine = panel

    _status, body, _ = pedir(base + "/")

    assert "Salud del sistema" in body
    for fuente in ("URLhaus", "OpenPhish", "Feodo Tracker", "AbuseIPDB", "Lista de nodos TOR"):
        assert fuente in body, f"falta {fuente} en el panel"
    assert "Última sincronización" in body
    assert "Versión de reglas" in body


def test_una_fuente_caida_se_ve_distinta_de_una_sana(tmp_path):
    """Lo importante del panel es que NO mienta: si una fuente falla tiene
    que decirlo, y ademas decir de cuando es la lista que esta en uso."""
    feeds_status.registrar(tmp_path, "URLhaus", True, 500)
    feeds_status.registrar(tmp_path, "URLhaus", False, error="timeout")

    guardado = feeds_status.leer(tmp_path)["URLhaus"]

    assert guardado["ok"] is False
    assert "demasiado" in guardado["error"], "el error se cuenta en castellano"
    assert guardado["ultimo_ok"], "tiene que recordar la ultima descarga buena"
    assert guardado["entradas"] == 500, "y cuantas reglas hay en uso ahora"


def test_urlhaus_y_openphish_se_registran_por_separado(tmp_path):
    """Las dos escriben en el MISMO archivo de listas, asi que mirando la
    fecha del archivo una fuente caida quedaria tapada por la otra."""
    feeds_status.registrar(tmp_path, "URLhaus", True, 1000)
    feeds_status.registrar(tmp_path, "OpenPhish", False, error="503")

    guardado = feeds_status.leer(tmp_path)

    assert guardado["URLhaus"]["ok"] is True
    assert guardado["OpenPhish"]["ok"] is False


def test_sin_datos_no_inventa_estado(tmp_path):
    assert feeds_status.leer(tmp_path) == {}


def test_abuseipdb_sin_api_key_se_reporta_asi(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")
    assert "sin API key" in body


def test_el_estado_de_tor_distingue_falla_de_apagado():
    tor = TorExitNodeList()
    estado = tor.estado()

    assert estado["ok"] is False
    assert estado["nodos"] == 0
    assert estado["ultimo_ok"] == 0.0


# ---------------- historial, detalle y buscador ----------------


def test_cada_conexion_tiene_link_de_detalle(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "verDetalle(" in body
    assert ">Detalle<" in body
    # El detalle viene embebido, no se pide al servidor al hacer clic.
    assert "detalle-fila" in body
    assert "Tiempo de decisión" in body
    assert "ID en el historial" in body


def test_el_buscador_encuentra_por_dominio(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/?q=sitio1")

    # Se mira SOLO la tabla del historial: los otros dominios aparecen igual
    # en la pestaña de estadisticas (top de destinos), que no filtra.
    tabla = body[body.index("Historial de conexiones"):body.index("tab-stats")]
    assert "sitio1.test" in tabla
    assert "sitio2.test" not in tabla


def test_buscar_trae_permitidas_y_bloqueadas(panel):
    """Auditar una IP es querer ver TODO lo que hizo, no solo lo que se le
    corto: por eso con busqueda se ignora el filtro de 'solo bloqueadas'."""
    _base, logger, _engine = panel

    filas = logger.buscar(texto="sitio1", limit=50)

    assert filas, "tendria que haber encontrado algo"
    assert any(f["blocked"] for f in filas)
    assert any(not f["blocked"] for f in filas)


def test_sin_busqueda_muestra_solo_bloqueos(panel):
    _base, logger, _engine = panel
    filas = logger.buscar(texto="", solo_bloqueadas=True, limit=50)
    assert filas and all(f["blocked"] for f in filas)


def test_una_busqueda_sin_resultados_lo_dice(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/?q=noexisteestedominio")
    assert "No hay conexiones que coincidan" in body


# ---------------- estadisticas ----------------


def test_las_estadisticas_salen_del_historial(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "Conexiones por hora" in body
    assert "Top 10 de destinos" in body
    assert "Bloqueos por motivo" in body
    assert "barra-fill" in body, "las barras se dibujan con divs, sin librerias"


def test_las_consultas_agregan_bien(panel):
    _base, logger, _engine = panel

    top = dict(logger.top_hosts(limit=10))
    motivos = dict(logger.bloqueos_por_motivo())
    por_hora = logger.por_hora(horas=24)

    assert sum(top.values()) == 12
    assert motivos["dominio en blocklist"] == 6
    assert por_hora and por_hora[0][1] == 12 and por_hora[0][2] == 6


# ---------------- exportacion ----------------


def test_exporta_csv_descargable(panel):
    base, _logger, _engine = panel
    status, body, headers = pedir(base + "/export.csv")

    assert status == 200
    assert "attachment" in headers.get("Content-Disposition", "")
    assert body.splitlines()[0].lstrip("﻿").startswith("id,timestamp")
    assert len(body.splitlines()) == 7  # 6 bloqueadas + encabezado


def test_exporta_json_con_todas_las_columnas(panel):
    base, _logger, _engine = panel
    status, body, _headers = pedir(base + "/export.json")

    assert status == 200
    datos = json.loads(body)
    assert len(datos) == 6
    assert set(datos[0]) == set(LoggerDB.COLUMNAS)


def test_exportar_respeta_el_filtro_del_buscador(panel):
    """Lo que ves es lo que exportas: si no, uno exporta creyendo que se
    lleva lo que estaba mirando y se lleva otra cosa."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/export.json?q=sitio1")

    datos = json.loads(body)
    assert datos and all("sitio1" in fila["host"] for fila in datos)


# ---------------- OSINT ----------------


def test_osint_consulta_un_dominio_de_la_lista_negra(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/osint?osint=malo.test")

    assert "SE BLOQUEA" in body
    assert "En lista negra" in body


def test_osint_sobre_un_dominio_limpio(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/osint?osint=bueno.test")

    assert "SE PERMITE" in body


def test_osint_no_registra_la_consulta_como_conexion(panel):
    """Consultar a mano no es navegar: si se registrara, el historial y las
    estadisticas quedarian contaminados por las propias consultas."""
    base, logger, _engine = panel
    antes = logger.stats()["total_requests"]

    pedir(base + "/osint?osint=malo.test")

    assert logger.stats()["total_requests"] == antes


def test_osint_vacio_solo_muestra_el_formulario(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/osint")

    assert "SE BLOQUEA" not in body and "SE PERMITE" not in body


def test_sin_estado_por_fuente_usa_la_fecha_del_archivo(tmp_path, monkeypatch):
    """El caso de toda instalacion que ya venia andando: las listas estan y
    son validas, pero se descargaron antes de que existiera este panel, asi
    que nadie anoto de donde salio cada una. Decir 'sin datos / nunca' ahi
    seria mentir por omision."""
    import secureproxy.config_loader as cl

    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)  # data/ vacia
    feeds = tmp_path / "blocklist_feeds.txt"
    feeds.write_text("malo1.test\nmalo2.test\n", encoding="utf-8")
    (tmp_path / "ip_blocklist_feeds.txt").write_text("1.2.3.4\n", encoding="utf-8")
    (tmp_path / "bl.txt").write_text("manual.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")

    logger = LoggerDB(str(tmp_path / "l.db"))
    engine = FilterEngine(
        blocklist=Blocklist([str(tmp_path / "bl.txt"), str(feeds)]),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        ip_blocklist=IPBlocklist(str(tmp_path / "ip_blocklist_feeds.txt")),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _status, body, _ = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    assert "lista cargada" in body, "tendria que apoyarse en la fecha del archivo"
    assert "Última sincronización" in body
    assert "nunca" not in body.split("Última sincronización")[1][:120]


def test_sin_listas_ni_estado_dice_que_hacer(panel, tmp_path, monkeypatch):
    """Y cuando de verdad no hay nada, que no deje al usuario adivinando."""
    import secureproxy.config_loader as cl

    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path / "vacio")
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "Actualizar listas" in body


# ---------------- exportar y sincronizar ----------------


def test_hay_un_solo_boton_de_exportar(panel):
    """Antes eran dos botones (CSV y JSON) al lado del de borrar cache. Ahora
    es uno solo que pregunta el formato."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert ">Exportar<" in body
    assert ">Exportar CSV<" not in body and ">Exportar JSON<" not in body
    assert "function exportar()" in body
    # Los dos endpoints siguen existiendo: lo que cambia es como se llegan.
    assert "/export.csv" in body and "/export.json" in body


def test_el_boton_de_exportar_arrastra_el_filtro_del_buscador(panel):
    """Si estas mirando una busqueda y exportas, tenes que llevarte ESA
    busqueda, no el historial entero."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "input[name=\"q\"]" in body
    assert "encodeURIComponent" in body


def test_hay_boton_para_sincronizar_las_listas(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "Sincronizar listas" in body
    assert "/sincronizar" in body


def test_sincronizar_vuelve_al_panel_al_instante(panel, monkeypatch):
    """Bajar tres feeds tarda segundos: la descarga va en un hilo aparte y la
    pagina vuelve enseguida, en vez de quedarse colgada esperando."""
    import secureproxy.proxy_server as ps

    llamadas = []
    monkeypatch.setattr(
        ps.ProxyRequestHandler, "_sincronizar_feeds",
        lambda self: (llamadas.append(True), self._redirect_to_dashboard())[1],
    )
    base, _logger, _engine = panel

    status, _body, _ = pedir(base + "/sincronizar")

    assert status == 200  # redirige al panel
    assert llamadas


def test_dos_pedidos_de_sincronizacion_no_se_pisan(panel):
    """Si dos pestañas aprietan el boton, la descarga se hace una sola vez."""
    import secureproxy.proxy_server as ps

    with ps.ProxyRequestHandler._sync_lock:
        ps.ProxyRequestHandler._sync_estado = "corriendo"
    try:
        base, _logger, _engine = panel
        _status, body, _ = pedir(base + "/")
        assert "Sincronizando las listas ahora" in body
    finally:
        with ps.ProxyRequestHandler._sync_lock:
            ps.ProxyRequestHandler._sync_estado = ""


def test_sin_api_key_el_panel_dice_como_arreglarlo(panel):
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert "sin API key" in body
    assert "ABUSEIPDB_API_KEY" in body and ".env" in body


def test_los_errores_de_descarga_se_cuentan_en_castellano(tmp_path):
    """Un fallo viene con 300 caracteres de traza de la libreria. Volcado tal
    cual en el panel es ilegible y no ayuda a decidir que hacer."""
    crudo = (
        "HTTPSConnectionPool(host='urlhaus.abuse.ch', port=443): Max retries "
        "exceeded with url: /downloads/hostfile/ (Caused by SSLError("
        "SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] ...')))"
    )
    feeds_status.registrar(tmp_path, "URLhaus", False, error=crudo)

    guardado = feeds_status.leer(tmp_path)["URLhaus"]["error"]

    assert len(guardado) < 100
    assert "certificado" in guardado
    assert "HTTPSConnectionPool" not in guardado


def test_cada_tipo_de_falla_dice_algo_distinto():
    assert "DNS" in feeds_status.resumir_error("getaddrinfo failed")
    assert "internet" in feeds_status.resumir_error("Connection refused")
    assert "demasiado" in feeds_status.resumir_error("Read timed out")
    assert "429" in feeds_status.resumir_error("HTTP 429 Too Many Requests")


# ---------------- actualizacion en vivo (SSE) ----------------


def test_la_pagina_ya_no_se_recarga_sola(panel):
    """El refresco cada 5 segundos recargaba la pagina entera: reseteaba el
    scroll, cerraba los detalles abiertos y borraba el buscador."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    assert 'http-equiv="refresh"' not in body
    assert "new EventSource('/eventos'" in body


def test_los_fragmentos_tienen_su_contenedor(panel):
    """El canal manda pedazos sueltos; cada uno necesita un lugar propio en
    la pagina donde reemplazarse."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    for contenedor in ("tarjetas", "salud", "historial", "estadisticas"):
        assert f'id="{contenedor}"' in body, f"falta el contenedor {contenedor}"


def test_el_javascript_no_tiene_saltos_de_linea_crudos(panel):
    """Regresion de un bug real: un '\\n' dentro de un texto de JavaScript se
    convirtio en un salto de linea de verdad al generar la pagina, partiendo
    el literal en dos y rompiendo el bloque <script> ENTERO. Como consecuencia
    dejaron de andar tambien las pestañas y el detalle, que viven ahi."""
    base, _logger, _engine = panel
    _status, body, _ = pedir(base + "/")

    script = body[body.index("<script>"):body.index("</script>")]
    for linea in script.splitlines():
        comillas = linea.count("'") - linea.count("\\'")
        assert comillas % 2 == 0, f"literal de JS sin cerrar en: {linea[:70]}"


def test_los_fragmentos_traen_todo_lo_que_cambia(panel):
    """Lo que se manda por el canal tiene que alcanzar para redibujar todo lo
    que se mueve, sin pedir la pagina de nuevo."""
    _base, logger, engine = panel
    import secureproxy.proxy_server as ps

    handler = ps.DashboardOnlyRequestHandler.__new__(ps.DashboardOnlyRequestHandler)
    handler.logger_db = logger
    handler.filter_engine = engine

    frag = handler._fragmentos("")

    assert set(frag) == {"revision", "tarjetas", "ruido", "salud", "historial", "estadisticas"}
    assert "Conexiones totales" in frag["tarjetas"]
    assert "Salud del sistema" in frag["salud"]
    assert "verDetalle(" in frag["historial"]


def test_la_revision_cambia_solo_cuando_cambio_algo(panel):
    """Si la revision no cambiara, se repintaria el historial cada 5 segundos
    y se cerrarian los detalles que el usuario tenga abiertos."""
    _base, logger, engine = panel
    import secureproxy.proxy_server as ps

    handler = ps.DashboardOnlyRequestHandler.__new__(ps.DashboardOnlyRequestHandler)
    handler.logger_db = logger
    handler.filter_engine = engine

    primera = handler._fragmentos("")["revision"]
    segunda = handler._fragmentos("")["revision"]
    assert primera == segunda, "sin actividad nueva, la revision no puede cambiar"

    logger.log_request("127.0.0.1", "CONNECT", "recien.test", 443, "/", True, reason="x")
    assert handler._fragmentos("")["revision"] != primera


def test_hay_un_tope_de_pestañas_conectadas(panel):
    """Cada pestaña abierta ocupa un hilo mientras dura: sin techo, unas
    cuantas ventanas olvidadas se comen el pool del proxy."""
    import secureproxy.proxy_server as ps

    assert ps.ProxyRequestHandler.MAX_CLIENTES_SSE >= 1

    base, _logger, _engine = panel
    with ps.ProxyRequestHandler._sse_lock:
        ps.ProxyRequestHandler._sse_clientes = ps.ProxyRequestHandler.MAX_CLIENTES_SSE
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            pedir(base + "/eventos")
        assert error.value.code == 503
    finally:
        with ps.ProxyRequestHandler._sse_lock:
            ps.ProxyRequestHandler._sse_clientes = 0


def test_el_canal_se_anuncia_como_stream_de_eventos(panel):
    import socket as _socket

    base, _logger, _engine = panel
    host, puerto = base.replace("http://", "").split(":")
    con = _socket.create_connection((host, int(puerto)), timeout=10)
    try:
        # El Host tiene que ser el real: un Host inventado ahora se rechaza,
        # que es justo la defensa contra DNS rebinding.
        con.sendall(f"GET /eventos HTTP/1.1\r\nHost: {host}:{puerto}\r\n\r\n".encode())
        con.settimeout(10)
        # Las cabeceras y el primer evento llegan en paquetes distintos, asi
        # que hay que leer hasta tener el evento (o quedarse sin tiempo).
        recibido = ""
        for _ in range(20):
            trozo = con.recv(8192)
            if not trozo:
                break
            recibido += trozo.decode("utf-8", "replace")
            if "data: " in recibido:
                break
    finally:
        con.close()

    assert "text/event-stream" in recibido
    assert "no-cache" in recibido
    assert "data: " in recibido, "el primer evento sale enseguida, sin esperar cambios"
