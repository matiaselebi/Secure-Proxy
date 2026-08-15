"""Tests de la Fase 2: registro enriquecido, rangos de IP, cryptojacking y
niveles de seguridad.

A diferencia de la Fase 1, acá SÍ se toca el camino del tráfico: cada cosa
puede cambiar qué se bloquea y qué pasa. Por eso los tests miran las dos
puntas: que la decisión sea la correcta, y que lo que se registra sea cierto.
"""

import socket
import sqlite3
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import update_geoip  # noqa: E402

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.geoip import GeoIP, ip_a_entero  # noqa: E402
from secureproxy.ip_ranges import IPRangeBlocklist  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy import proxy_server  # noqa: E402
from secureproxy.proxy_server import (  # noqa: E402
    build_dashboard_server,
    build_proxy_server,
)
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
)

ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def pedir(url):
    with ABRIDOR.open(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


def motor(tmp_path, **extra):
    (tmp_path / "bl.txt").write_text("malo.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("permitido.test\n", encoding="utf-8")
    (tmp_path / "mining.txt").write_text("nanopool.org\nethermine.org\n", encoding="utf-8")
    base = dict(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        ip_blocklist=IPBlocklist(str(tmp_path / "ip.txt")),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
        mining_list=Blocklist(str(tmp_path / "mining.txt")),
        # Los escenarios de tráfico usan un backend en 127.0.0.1 con puerto
        # efímero: sin esto lo cortaría la política de destino.
        allow_internal_destinations=True,
    )
    base.update(extra)
    return FilterEngine(**base)


# ---------------- rangos de IP (FireHOL) ----------------


def test_una_ip_dentro_de_un_rango_se_reconoce(tmp_path):
    """FireHOL publica RANGOS, no IPs sueltas: comparar por igualdad -como
    hace la lista de Feodo- no encontraria nada."""
    (tmp_path / "r.netset").write_text("203.0.113.0/24\n198.51.100.7\n", encoding="utf-8")
    lista = IPRangeBlocklist(str(tmp_path / "r.netset"))

    assert lista.is_blocked("203.0.113.1")
    assert lista.is_blocked("203.0.113.254")
    assert lista.is_blocked("198.51.100.7")
    assert not lista.is_blocked("203.0.114.1")
    assert not lista.is_blocked("198.51.100.8")


def test_los_rangos_que_se_pisan_se_fusionan(tmp_path):
    """Fusionarlos deja la lista ordenada y sin superposiciones, que es lo
    que permite buscar por biseccion con una sola comparacion."""
    (tmp_path / "r.netset").write_text(
        "10.0.0.0/24\n10.0.1.0/24\n10.0.0.128/25\n", encoding="utf-8"
    )
    lista = IPRangeBlocklist(str(tmp_path / "r.netset"))

    assert len(lista) == 1, "los tres rangos son contiguos: es uno solo"
    assert lista.is_blocked("10.0.0.5") and lista.is_blocked("10.0.1.200")


def test_lo_que_no_es_una_ipv4_no_rompe_la_carga(tmp_path):
    (tmp_path / "r.netset").write_text(
        "# comentario\n\ncualquier cosa\n2001:db8::/32\n1.2.3.0/24\n", encoding="utf-8"
    )
    lista = IPRangeBlocklist(str(tmp_path / "r.netset"))

    assert len(lista) == 1
    assert not lista.is_blocked("2001:db8::1")
    assert lista.is_blocked("1.2.3.4")


def test_la_busqueda_no_se_arrastra_con_miles_de_rangos(tmp_path):
    """20.000 consultas contra 5.000 rangos tienen que resolverse rapido: el
    proxy hace esta pregunta en CADA conexion."""
    import random
    import time

    lineas = [f"{random.randint(1, 223)}.{random.randint(0, 255)}.0.0/16" for _ in range(5000)]
    (tmp_path / "r.netset").write_text("\n".join(lineas), encoding="utf-8")
    lista = IPRangeBlocklist(str(tmp_path / "r.netset"))

    inicio = time.time()
    for _ in range(20000):
        lista.is_blocked("8.8.8.8")
    assert time.time() - inicio < 2.0


def test_el_motor_bloquea_por_rango(tmp_path):
    (tmp_path / "r.netset").write_text("8.8.8.0/24\n", encoding="utf-8")
    engine = motor(tmp_path, ip_ranges=IPRangeBlocklist(str(tmp_path / "r.netset")))

    decision = engine.evaluate("dns.google")

    if decision.resolved_ip and decision.resolved_ip.startswith("8.8.8."):
        assert decision.blocked
        assert "FireHOL" in decision.reason


# ---------------- cryptojacking ----------------


def test_un_pool_de_mineria_se_bloquea_con_su_propio_motivo(tmp_path):
    """El motivo importa tanto como el bloqueo: cuando salta esto, lo que hay
    que hacer NO es agregar una excepcion sino buscar que proceso se conecto."""
    engine = motor(tmp_path)

    decision = engine.evaluate("eth-eu1.nanopool.org")

    assert decision.blocked
    assert "cryptojacking" in decision.reason
    assert "blocklist" not in decision.reason


def test_la_lista_blanca_le_gana_a_la_de_mineria(tmp_path):
    """Si alguien mina a proposito, tiene que poder permitirlo."""
    engine = motor(tmp_path)
    # Se escribe DESPUES de crear el motor: motor() arma la lista blanca de
    # cero y pisaria el archivo.
    (tmp_path / "al.txt").write_text("nanopool.org\n", encoding="utf-8")
    engine.allowlist.reload()

    assert not engine.evaluate("nanopool.org").blocked


def test_la_lista_de_pools_que_se_distribuye_tiene_los_mas_usados():
    lista = (Path(__file__).resolve().parent.parent / "data" / "mining_pools.txt").read_text(
        encoding="utf-8"
    )
    for pool in ("nanopool.org", "ethermine.org", "minexmr.com", "nicehash.com"):
        assert pool in lista


def test_los_destinos_insistentes_se_detectan_por_la_forma_del_trafico(tmp_path):
    """No se mira el contenido -va cifrado-: alcanza con que un destino
    aparezca muchisimas veces mientras el resto aparece poco."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(45):
        db.log_request("127.0.0.1", "CONNECT", "pool-sospechoso.test", 443, "/", False)
    for i in range(10):
        db.log_request("127.0.0.1", "CONNECT", f"normal{i}.test", 443, "/", False)

    sostenidas = db.conexiones_sostenidas(minimo=30, horas=6)

    assert len(sostenidas) == 1
    assert sostenidas[0][0] == "pool-sospechoso.test"
    assert sostenidas[0][1] == 45


def test_los_bloqueados_no_cuentan_como_destinos_insistentes(tmp_path):
    """Si ya se bloquean, no hay nada que investigar: seria ruido."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(50):
        db.log_request("127.0.0.1", "CONNECT", "ya-bloqueado.test", 443, "/", True, reason="x")

    assert db.conexiones_sostenidas(minimo=30, horas=6) == []


# ---------------- niveles de seguridad ----------------


@pytest.fixture
def panel(tmp_path, monkeypatch):
    import secureproxy.config_loader as cl

    (tmp_path / "config").mkdir()
    origen = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
    (tmp_path / "config" / "config.yaml").write_text(
        origen.read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)

    engine = motor(tmp_path)
    logger = LoggerDB(str(tmp_path / "l.db"))
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", engine, tmp_path
    server.shutdown()


def test_cada_nivel_fija_todas_sus_opciones(panel):
    base, engine, _tmp = panel

    pedir(base + "/nivel?v=estricto")
    assert engine.mode == "enforce" and engine.abuseipdb_min_score == 25

    pedir(base + "/nivel?v=paranoico")
    assert engine.mode == "audit"
    assert engine.abuseipdb_min_score == 10
    assert engine.block_unknown_domains is True

    pedir(base + "/nivel?v=normal")
    assert engine.mode == "enforce"
    assert engine.abuseipdb_min_score == 50
    assert engine.block_unknown_domains is False


def test_el_nivel_queda_escrito_en_el_archivo(panel):
    """Tiene que sobrevivir a un reinicio, no vivir solo en memoria."""
    base, _engine, tmp = panel

    pedir(base + "/nivel?v=estricto")

    yaml = (tmp / "config" / "config.yaml").read_text(encoding="utf-8")
    assert "abuseipdb_min_score: 25" in yaml
    assert 'security_level: "estricto"' in yaml
    assert "# " in yaml, "los comentarios del archivo no se pierden"


def test_si_tocas_una_opcion_suelta_el_nivel_pasa_a_personalizado(panel):
    """Lo honesto es decir 'personalizado' y no seguir mostrando un nivel que
    ya no describe lo que hay puesto."""
    base, engine, _tmp = panel
    pedir(base + "/nivel?v=normal")

    pedir(base + "/config?k=abuseipdb_min_score&v=33")

    _status, body = pedir(base + "/")
    assert "personalizado" in body or "no coincide con" in body
    assert engine.abuseipdb_min_score == 33


def test_un_nivel_inventado_no_hace_nada(panel):
    base, engine, _tmp = panel
    antes = engine.abuseipdb_min_score

    pedir(base + "/nivel?v=ultra-paranoico-turbo")

    assert engine.abuseipdb_min_score == antes


def test_el_paranoico_esta_marcado_como_diagnostico(panel):
    """Aplicado de verdad deja sin internet: la pantalla tiene que decirlo
    antes de que alguien lo prenda pensando que es 'mas seguridad'."""
    base, _engine, _tmp = panel
    _status, body = pedir(base + "/")

    assert "Paranoico" in body
    assert "NO bloquea" in body or "diagnóstico" in body


def test_bloquear_dominios_desconocidos_deja_pasar_la_lista_blanca(tmp_path):
    engine = motor(tmp_path, block_unknown_domains=True)

    assert not engine.evaluate("permitido.test").blocked
    decision = engine.evaluate("cualquier-otra-cosa.test")
    assert decision.blocked
    assert "desconocido" in decision.reason


# ---------------- geolocalizacion ----------------


def test_importa_los_csv_y_resuelve_pais_y_asn(tmp_path):
    paises = "8.8.8.0,8.8.8.255,US\n190.0.0.0,190.255.255.255,AR\n"
    asns = "8.8.8.0,8.8.8.255,AS15169,Google LLC\n190.0.0.0,190.255.255.255,AS10318,Telecom Argentina\n"
    db = tmp_path / "geo.db"

    total = update_geoip.importar(paises, asns, db)

    geo = GeoIP(str(db))
    assert total == 2
    assert geo.buscar("8.8.8.8") == {"pais": "US", "asn": "AS15169", "proveedor": "Google LLC"}
    assert geo.buscar("190.55.1.1")["pais"] == "AR"


def test_una_ip_fuera_de_todo_rango_no_inventa_pais(tmp_path):
    db = tmp_path / "geo.db"
    update_geoip.importar("8.8.8.0,8.8.8.255,US\n", "", db)

    assert GeoIP(str(db)).buscar("127.0.0.1")["pais"] == ""


def test_sin_base_descargada_el_proxy_funciona_igual(tmp_path):
    """La geolocalizacion enriquece el registro, no participa de la decision
    de bloquear: que falte no puede romper nada."""
    geo = GeoIP(str(tmp_path / "no_existe.db"))

    assert geo.disponible is False
    assert geo.buscar("8.8.8.8") == {"pais": "", "asn": "", "proveedor": ""}


def test_la_resolucion_es_local_y_rapida(tmp_path):
    """La regla que manda: NUNCA una consulta a una API por conexion."""
    import time

    filas = "\n".join(f"{i}.0.0.0,{i}.255.255.255,C{i}" for i in range(1, 224))
    db = tmp_path / "geo.db"
    update_geoip.importar(filas, "", db)
    geo = GeoIP(str(db))

    inicio = time.time()
    for _ in range(5000):
        geo.buscar("8.8.8.8")
    assert time.time() - inicio < 1.0


def test_ip_a_entero_rechaza_lo_que_no_es_ipv4():
    assert ip_a_entero("1.2.3.4") == 16909060
    assert ip_a_entero("2001:db8::1") is None
    assert ip_a_entero("chau") is None


# ---------------- registro enriquecido ----------------


def test_se_guardan_ip_de_destino_pais_asn_y_proveedor(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))

    db.log_request(
        "127.0.0.1", "CONNECT", "ejemplo.test", 443, "/", True, reason="prueba",
        dest_ip="8.8.8.8", country="US", asn="AS15169", provider="Google LLC",
    )

    fila = db.buscar(limit=1)[0]
    assert fila["dest_ip"] == "8.8.8.8"
    assert fila["country"] == "US"
    assert fila["asn"] == "AS15169"
    assert fila["provider"] == "Google LLC"


def test_una_base_vieja_se_actualiza_sin_perder_el_historial(tmp_path):
    """Quien ya venia usando el proxy tiene una tabla sin las columnas
    nuevas. Se agregan con ALTER TABLE en vez de recrear la tabla, asi no se
    pierde nada."""
    ruta = tmp_path / "vieja.db"
    con = sqlite3.connect(str(ruta))
    con.execute(
        "CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, client_ip TEXT, method TEXT, host TEXT, "
        "port INTEGER, path TEXT, blocked INTEGER NOT NULL, reason TEXT, "
        "duration_ms REAL)"
    )
    con.execute(
        "INSERT INTO requests (timestamp, client_ip, method, host, port, path, blocked) "
        "VALUES ('2026-01-01T00:00:00+00:00', '127.0.0.1', 'GET', 'viejo.test', 80, '/', 1)"
    )
    con.commit()
    con.close()

    db = LoggerDB(str(ruta))

    filas = db.buscar(limit=10)
    assert len(filas) == 1, "la fila vieja sigue estando"
    assert filas[0]["host"] == "viejo.test"
    assert filas[0]["country"] is None or filas[0]["country"] == ""


def test_el_buscador_encuentra_por_pais_y_por_ip_de_destino(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_request("127.0.0.1", "CONNECT", "uno.test", 443, "/", False,
                   dest_ip="8.8.8.8", country="US", provider="Google LLC")
    db.log_request("127.0.0.1", "CONNECT", "dos.test", 443, "/", False,
                   dest_ip="190.1.1.1", country="AR", provider="Telecom")

    assert len(db.buscar(texto="US", limit=10)) == 1
    assert db.buscar(texto="8.8.8.8", limit=10)[0]["host"] == "uno.test"
    assert db.buscar(texto="Telecom", limit=10)[0]["host"] == "dos.test"


def test_el_detalle_muestra_los_campos_nuevos(tmp_path):
    engine = motor(tmp_path)
    logger = LoggerDB(str(tmp_path / "l.db"))
    logger.log_request("127.0.0.1", "CONNECT", "x.test", 443, "/", True, reason="p",
                       dest_ip="8.8.8.8", country="US", asn="AS15169", provider="Google")
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _status, body = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    for etiqueta in ("IP de destino", "País", "ASN", "Proveedor"):
        assert etiqueta in body
    assert "AS15169" in body and "Google" in body


# ---------------- el registro enriquecido, de punta a punta ----------------
#
# Los tests de arriba prueban las piezas por separado (la base de geo resuelve,
# el logger guarda las columnas). Estos levantan el proxy de verdad y hacen
# tráfico a través de él, que es donde apareció el problema real: la decisión
# del motor solo trae la IP cuando necesitó resolverla para decidir, así que
# las conexiones PERMITIDAS quedaban registradas sin destino, sin país y sin
# proveedor.


class _Backend(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def _geo_de_loopback(tmp_path):
    """Base de geo de prueba que cubre 127.0.0.0/8."""
    db = tmp_path / "geo.db"
    update_geoip.importar(
        "127.0.0.0,127.255.255.255,AR\n",
        "127.0.0.0,127.255.255.255,AS1234,Proveedor De Prueba\n",
        db,
    )
    return GeoIP(str(db))


@pytest.fixture()
def escenario(tmp_path):
    """Backend real + proxy real + base de geo, todo en 127.0.0.1."""
    backend = HTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    engine = motor(tmp_path)
    logger = LoggerDB(str(tmp_path / "l.db"))
    proxy = build_proxy_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, geoip=_geo_de_loopback(tmp_path),
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield {
            "backend_port": backend.server_address[1],
            "proxy_port": proxy.server_address[1],
            "logger": logger,
            "engine": engine,
        }
    finally:
        proxy.shutdown()
        backend.shutdown()


def _ultima(logger, espera=5.0):
    """La ultima conexion registrada, esperando a que aparezca.

    El proxy escribe la respuesta al cliente y RECIEN DESPUES loguea, asi que
    hay una carrera real: `requests.get` puede volver antes de que la fila
    exista. En produccion es lo correcto (no se le hace esperar al cliente
    por el registro); en el test hay que esperarla.
    """
    limite = time.time() + espera
    while True:
        filas = logger.buscar(solo_bloqueadas=False, limit=1)
        if filas:
            return filas[0]
        if time.time() > limite:
            raise AssertionError("no se registro ninguna conexion")
        time.sleep(0.05)


def test_una_conexion_permitida_queda_registrada_con_ip_pais_asn_y_proveedor(escenario):
    respuesta = requests.get(
        f"http://127.0.0.1:{escenario['backend_port']}/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy_port']}"},
        timeout=10,
    )
    assert respuesta.status_code == 200

    fila = _ultima(escenario["logger"])
    assert fila["blocked"] == 0
    assert fila["dest_ip"] == "127.0.0.1"
    assert fila["country"] == "AR"
    assert fila["asn"] == "AS1234"
    assert fila["provider"] == "Proveedor De Prueba"


def test_un_dominio_de_la_allowlist_tambien_queda_con_su_destino(escenario, tmp_path):
    """La allowlist también resuelve el destino para aplicar la barrera de LAN."""
    (tmp_path / "al.txt").write_text("127.0.0.1\n", encoding="utf-8")
    escenario["engine"].allowlist.reload()
    assert escenario["engine"].evaluate("127.0.0.1").resolved_ip == "127.0.0.1"

    requests.get(
        f"http://127.0.0.1:{escenario['backend_port']}/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy_port']}"},
        timeout=10,
    )

    fila = _ultima(escenario["logger"])
    assert fila["dest_ip"] == "127.0.0.1"
    assert fila["country"] == "AR"


def test_un_tunel_connect_registra_la_ip_real_del_socket(escenario):
    sock = socket.create_connection(("127.0.0.1", escenario["proxy_port"]), timeout=10)
    destino = f"127.0.0.1:{escenario['backend_port']}"
    sock.sendall(f"CONNECT {destino} HTTP/1.1\r\nHost: {destino}\r\n\r\n".encode())
    assert b"200" in sock.recv(1024)
    sock.close()
    time.sleep(0.3)

    fila = _ultima(escenario["logger"])
    assert fila["method"] == "CONNECT"
    assert fila["dest_ip"] == "127.0.0.1"
    assert fila["provider"] == "Proveedor De Prueba"


def test_un_dominio_bloqueado_no_se_resuelve_solo_para_adornar_el_registro(
    escenario, monkeypatch
):
    """Si se cortó por blocklist, no le mandamos una consulta DNS igual."""
    def no_deberia_llamarse(host):  # pragma: no cover
        raise AssertionError(f"se resolvió {host} después de bloquearlo")

    monkeypatch.setattr(proxy_server, "resolve_host_to_ip", no_deberia_llamarse)

    respuesta = requests.get(
        "http://malo.test/",
        proxies={"http": f"http://127.0.0.1:{escenario['proxy_port']}"},
        timeout=10,
    )

    assert respuesta.status_code == 403
    fila = _ultima(escenario["logger"])
    assert fila["blocked"] == 1
    assert fila["dest_ip"] == ""


def _detalle_de(tmp_path, filas, con_base):
    engine = motor(tmp_path)
    logger = LoggerDB(str(tmp_path / "l.db"))
    for kwargs in filas:
        logger.log_request("127.0.0.1", "CONNECT", kwargs.pop("host"), 443, "/",
                           kwargs.pop("blocked", True), **kwargs)
    geo = _geo_de_loopback(tmp_path) if con_base else GeoIP(str(tmp_path / "no_existe.db"))
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, geoip=geo,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        return pedir(f"http://127.0.0.1:{server.server_address[1]}/")[1]
    finally:
        server.shutdown()


def test_el_detalle_explica_por_que_falta_el_pais_segun_el_caso(tmp_path):
    """Tres motivos distintos, tres mensajes distintos: mandar a descargar la
    base cuando ya está descargada no ayuda a nadie."""
    sin_ip = _detalle_de(tmp_path, [{"host": "malo.test", "reason": "blocklist"}], con_base=True)
    assert "se bloqueó antes de resolver el dominio" in sin_ip

    fuera = _detalle_de(tmp_path, [{"host": "x.test", "dest_ip": "8.8.8.8"}], con_base=True)
    assert "esa IP no está en la base" in fuera

    sin_base = _detalle_de(tmp_path, [{"host": "x.test", "dest_ip": "8.8.8.8"}], con_base=False)
    assert "sin base de geolocalización" in sin_base


def test_la_pestana_de_configuracion_no_repite_titulos(tmp_path):
    """El bloque de niveles se metió arriba del de modo, y quedaba el título
    'Modo de filtrado' dos veces con la descripción separada de sus tarjetas."""
    engine = motor(tmp_path)
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _status, body = pedir(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()

    titulos = [t for t in body.split("<h2>") if t.startswith("Modo de filtrado")]
    assert len(titulos) == 1
    # y el nivel va antes del modo, que es el orden de lo general a lo puntual
    assert body.index("Nivel de seguridad") < body.index("Modo de filtrado")
