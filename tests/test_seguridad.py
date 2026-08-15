"""Regresiones de la auditoría de seguridad.

Cada test de acá corresponde a un agujero que existía de verdad y que se
verificó explotable antes de arreglarlo. El comentario de cada uno dice qué
pasaba, porque un test de seguridad sin esa explicación es un test que
alguien borra en seis meses por parecer redundante.
"""

import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import (  # noqa: E402
    _es_destino_interno,
    _headers_para_reenviar,
    _partir_destino,
    build_dashboard_server,
    build_proxy_server,
)
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
    escribir_atomico,
    resolve_host_to_ip,
)
from secureproxy.validation import normalizar_host_de_trafico  # noqa: E402


def _motor(tmp_path, **extra):
    (tmp_path / "bl.txt").write_text("malicioso.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    base = dict(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    base.update(extra)
    return FilterEngine(**base)


def _cruda(puerto, pedido: str, espera=3.0) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=espera)
    try:
        con.sendall(pedido.encode())
        con.settimeout(espera)
        datos = b""
        try:
            while len(datos) < 65536:
                trozo = con.recv(4096)
                if not trozo:
                    break
                datos += trozo
                if b"\r\n\r\n" in datos:
                    break
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


# ================= panel: CSRF y DNS rebinding =================


@pytest.fixture()
def panel(tmp_path):
    engine = _motor(tmp_path)
    servidor = build_dashboard_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield servidor.server_address[1], engine
    finally:
        servidor.shutdown()


ACCIONES = [
    "/config?k=mode&v=audit",
    "/nivel?v=paranoico",
    "/allow?domain=c2.attacker.com",
    "/blockdomain?domain=banco.com",
    "/ocultar?domain=c2.attacker.com",
    "/clear-cache",
    # Apagar es la más grave de todas: una página cualquiera que te apague el
    # proxy te deja la máquina sin filtrado y encima sin internet.
    "/apagar",
]


@pytest.mark.parametrize("ruta", ACCIONES)
def test_una_web_cualquiera_no_puede_cambiar_la_configuracion(panel, ruta):
    """CSRF. Todas las acciones son GET sin token, así que cualquier página
    que visites podía hacer <img src="http://127.0.0.1:8889/config?k=mode&
    v=audit"> y dejar el proxy sin bloquear nada, o meter su propio dominio
    en la lista blanca. No necesita leer la respuesta, así que la política
    de mismo origen del navegador no protegía de esto."""
    puerto, _engine = panel

    respuesta = _cruda(puerto, (
        f"GET {ruta} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{puerto}\r\n"
        "Sec-Fetch-Site: cross-site\r\n"
        "Origin: https://sitio-malicioso.com\r\n"
        "Connection: close\r\n\r\n"
    ))

    assert "403" in respuesta.split("\r\n")[0]


@pytest.mark.parametrize("ruta", ACCIONES)
def test_tambien_se_frena_por_referer_sin_sec_fetch(panel, ruta):
    """Navegadores viejos no mandan Sec-Fetch-Site."""
    puerto, _engine = panel

    respuesta = _cruda(puerto, (
        f"GET {ruta} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{puerto}\r\n"
        "Referer: https://sitio-malicioso.com/pagina\r\n"
        "Connection: close\r\n\r\n"
    ))

    assert "403" in respuesta.split("\r\n")[0]


def test_el_panel_de_verdad_sigue_funcionando(panel):
    """La defensa no puede romper el uso normal: el panel hablando consigo
    mismo, y alguien escribiendo la dirección en la barra."""
    puerto, _engine = panel

    desde_el_panel = _cruda(puerto, (
        f"GET /config?k=abuseipdb_min_score&v=50 HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
        "Sec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n"
    ))
    desde_la_barra = _cruda(puerto, (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
        "Sec-Fetch-Site: none\r\nConnection: close\r\n\r\n"
    ))

    assert "303" in desde_el_panel.split("\r\n")[0]
    assert "200" in desde_la_barra.split("\r\n")[0]


def test_un_host_ajeno_no_llega_ni_a_leer(panel):
    """DNS rebinding. El atacante publica attacker.com con TTL 0, te hace
    entrar y después reapunta ese nombre a 127.0.0.1: a partir de ahí su
    JavaScript queda del MISMO origen que el panel y puede leer todo tu
    historial de navegación. Se corta mirando el Host, que es el nombre que
    el navegador manda y el atacante no puede disimular."""
    puerto, _engine = panel

    for ruta in ("/dashboard", "/export.json", "/export.csv"):
        respuesta = _cruda(puerto, (
            f"GET {ruta} HTTP/1.1\r\nHost: attacker.com\r\nConnection: close\r\n\r\n"
        ))
        assert "403" in respuesta.split("\r\n")[0], ruta


def test_health_queda_accesible_para_securecenter(panel):
    """No cambia nada ni expone datos: es el chequeo de vida."""
    puerto, _engine = panel

    respuesta = _cruda(puerto, (
        f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\nConnection: close\r\n\r\n"
    ))

    assert "200" in respuesta.split("\r\n")[0]


# ================= panel: XSS =================


def test_un_host_con_comillas_no_ejecuta_javascript(tmp_path):
    """XSS almacenado. El host viene del tráfico y no se valida: un proceso
    local puede pedir CONNECT hacia un "dominio" con comillas. Ese texto
    terminaba dentro de onclick="return confirm('... DOMINIO ...')" escapado
    como HTML, y eso NO alcanza: el navegador decodifica las entidades del
    atributo ANTES de pasarle el texto al parser de JavaScript, así que
    &#x27; vuelve a ser comilla y cierra el literal. Se verificó en un
    navegador real que el JavaScript del payload se ejecutaba al hacer clic
    en "Permitir"."""
    engine = _motor(tmp_path)
    logger = LoggerDB(str(tmp_path / "l.db"))
    payload = "x'-alert(1)-'.com"
    logger.log_request("127.0.0.1", "CONNECT", payload, 443, "/", True, reason="prueba")
    servidor = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with abridor.open(f"http://127.0.0.1:{servidor.server_address[1]}/") as r:
            cuerpo = r.read().decode()
    finally:
        servidor.shutdown()

    # El dato viaja por data-dominio, que es contexto de atributo, y ahí el
    # escape de HTML sí alcanza.
    assert "confirmarAccion(this," in cuerpo
    # y en NINGÚN atributo de evento aparece el payload sin escapar
    for linea in cuerpo.splitlines():
        for evento in ("onclick=", "onsubmit="):
            if evento in linea:
                manejador = linea.split(evento, 1)[1]
                assert "alert(1)" not in manejador.split(">")[0]


# ================= tráfico: bypass y crashes =================


def test_un_punto_al_final_ya_no_esquiva_las_listas(tmp_path):
    """Bypass de un solo carácter: el DNS trata "nanopool.org." y
    "nanopool.org" como el mismo nombre y resuelven igual, pero las listas
    comparaban texto y con el punto no matcheaba nada."""
    engine = _motor(tmp_path)

    assert engine.evaluate("malicioso.test").blocked is True
    assert engine.evaluate("malicioso.test.").blocked is True
    assert engine.evaluate("MALICIOSO.TEST.").blocked is True


def test_el_normalizador_deja_los_nombres_como_los_publican_los_feeds():
    assert normalizar_host_de_trafico("NANOPOOL.ORG.") == "nanopool.org"
    assert normalizar_host_de_trafico("ejemplo-ñ.com") == "xn--ejemplo--k3a.com"
    assert normalizar_host_de_trafico("") == ""


def test_un_nombre_larguisimo_no_tumba_la_resolucion():
    """El codec IDNA levanta UnicodeError, que NO es un gaierror, así que la
    excepción salía del motor y mataba el hilo de la conexión sin registrar
    nada. Y los nombres con etiquetas larguísimas son justo el patrón de los
    dominios generados por algoritmo: el caso que más querés ver era el que
    rompía el proxy."""
    assert resolve_host_to_ip("a" * 64 + ".com") is None
    assert resolve_host_to_ip("\x80\x81.com") is None


@pytest.mark.parametrize("destino,esperado", [
    ("sitio.com:443", ("sitio.com", 443)),
    ("sitio.com", ("sitio.com", 443)),
    ("[::1]:443", ("::1", 443)),          # IPv6: antes quedaba host="["
    ("[::1]", ("::1", 443)),
    ("sitio.com:abc", ("sitio.com", None)),   # antes: ValueError y hilo muerto
    ("sitio.com:0", ("sitio.com", None)),
    ("sitio.com:99999", ("sitio.com", None)),
    ("", ("", None)),
])
def test_el_destino_del_connect_se_parsea_sin_romperse(destino, esperado):
    assert _partir_destino(destino) == esperado


# ================= tráfico: política de destino =================


@pytest.fixture()
def proxy(tmp_path):
    engine = _motor(tmp_path)
    servidor = build_proxy_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown()


@pytest.mark.parametrize("destino", [
    "127.0.0.1:8889",        # el propio panel
    "localhost:80",
    "192.168.1.1:80",        # el router
    "10.0.0.5:80",
    "169.254.169.254:80",    # metadatos de nube
])
def test_no_se_puede_tunelizar_hacia_adentro(proxy, destino):
    """El proxy dejaba abrir un túnel TCP a cualquier destino y a cualquier
    puerto. Verificado antes del arreglo: se llegaba al propio dashboard, al
    router y hasta a un SSH local, del que se leyó el banner. Con `proxy.host`
    en 0.0.0.0 eso convierte al proxy en un relay abierto con pivote a los
    servicios locales de la máquina."""
    respuesta = _cruda(proxy, f"CONNECT {destino} HTTP/1.1\r\nHost: {destino}\r\n\r\n")

    assert "403" in respuesta.split("\r\n")[0], respuesta.split("\r\n")[0]


@pytest.mark.parametrize("puerto", [22, 445, 3389, 25, 6379])
def test_no_se_puede_tunelizar_a_puertos_que_no_son_web(proxy, puerto):
    """Un proxy web que tuneliza a cualquier puerto es un canal TCP
    arbitrario: sirve para llegar al SSH, al SMB o al RDP de la LAN."""
    destino = f"ejemplo.com:{puerto}"
    respuesta = _cruda(proxy, f"CONNECT {destino} HTTP/1.1\r\nHost: {destino}\r\n\r\n")

    assert "403" in respuesta.split("\r\n")[0]


def test_un_content_length_que_no_es_numero_no_mata_el_hilo(proxy):
    """Antes: int() pelado, ValueError, hilo muerto y el cliente sin ninguna
    respuesta."""
    respuesta = _cruda(proxy, (
        "POST http://ejemplo.com/ HTTP/1.1\r\nHost: ejemplo.com\r\n"
        "Content-Length: abc\r\n\r\n"
    ))

    assert "400" in respuesta.split("\r\n")[0]


def test_un_content_length_gigante_se_rechaza_en_vez_de_reservar_memoria(proxy):
    """Medido antes del arreglo: con "Content-Length: 3000000000" el proceso
    saltaba de 1.0 GB a 3.9 GB de memoria comprometida al instante. En
    Windows, que no hace overcommit, unos pocos pedidos dejan la máquina sin
    memoria."""
    respuesta = _cruda(proxy, (
        "POST http://ejemplo.com/ HTTP/1.1\r\nHost: ejemplo.com\r\n"
        "Content-Length: 3000000000\r\n\r\n"
    ))

    assert "413" in respuesta.split("\r\n")[0]


def test_un_content_length_negativo_no_deja_el_hilo_colgado(proxy):
    """-1 es truthy, así que entraba a read(-1), que lee hasta EOF: el hilo
    quedaba esperando a que el cliente cerrara."""
    respuesta = _cruda(proxy, (
        "POST http://ejemplo.com/ HTTP/1.1\r\nHost: ejemplo.com\r\n"
        "Content-Length: -1\r\n\r\n"
    ))

    assert "413" in respuesta.split("\r\n")[0]


def test_un_puerto_invalido_en_connect_responde_en_vez_de_morir(proxy):
    respuesta = _cruda(proxy, "CONNECT ejemplo.com:abc HTTP/1.1\r\nHost: x\r\n\r\n")

    assert "400" in respuesta.split("\r\n")[0]


def test_es_destino_interno_reconoce_lo_que_tiene_que_reconocer():
    for interna in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1",
                    "169.254.169.254", "::1", "0.0.0.0"):
        assert _es_destino_interno(interna) is True, interna
    for publica in ("8.8.8.8", "1.1.1.1", "ejemplo.com"):
        assert _es_destino_interno(publica) is False, publica


def test_un_dominio_que_apunta_adentro_tampoco_pasa(tmp_path, monkeypatch):
    """Chequear solo el texto del host dejaba el camino abierto: un dominio
    público puede apuntar tranquilamente a 127.0.0.1."""
    import secureproxy.filter_engine as fe

    engine = _motor(tmp_path)
    monkeypatch.setattr(fe, "resolve_host_to_ip", lambda host: "127.0.0.1")

    decision = engine.evaluate("parece-publico.com")

    assert decision.blocked is True
    assert "interna" in decision.reason


def test_la_allowlist_no_saltea_la_proteccion_de_la_red_interna(tmp_path, monkeypatch):
    """Permitir un nombre no debe convertir el proxy en un pivote hacia la LAN.

    La excepción de dominio gana sobre las fuentes de reputación, pero no sobre
    la barrera de destinos internos. Esa barrera solo se afloja con la opción
    explícita ``allow_internal_destinations``.
    """
    import secureproxy.filter_engine as fe

    engine = _motor(tmp_path)
    engine.allowlist.add_and_reload("permitido.test")
    monkeypatch.setattr(fe, "resolve_host_to_ip", lambda host: "127.0.0.1")

    decision = engine.evaluate("permitido.test")

    assert decision.blocked is True
    assert "interna" in decision.reason


def test_la_excepcion_explicita_de_red_interna_sigue_funcionando(tmp_path, monkeypatch):
    import secureproxy.filter_engine as fe

    engine = _motor(tmp_path, allow_internal_destinations=True)
    engine.allowlist.add_and_reload("panel-casero.test")
    monkeypatch.setattr(fe, "resolve_host_to_ip", lambda host: "192.168.1.20")

    decision = engine.evaluate("panel-casero.test")

    assert decision.blocked is False
    assert decision.resolved_ip == "192.168.1.20"


def test_se_puede_permitir_a_proposito(tmp_path):
    """Quien quiera proxear algo de su propia red tiene que poder."""
    engine = _motor(tmp_path, allow_internal_destinations=True)

    assert engine.evaluate("cualquier-cosa.test").blocked is False


# ================= tráfico: headers =================


def test_no_se_filtran_las_credenciales_del_proxy_al_destino():
    """Proxy-Authorization es la credencial del proxy: mandarla al sitio de
    destino es entregarle una contraseña que no es suya."""
    from email.message import Message

    headers = Message()
    for clave, valor in [
        ("Host", "sitio.com"), ("Proxy-Authorization", "Basic secreto"),
        ("Connection", "keep-alive, X-Interno"), ("X-Interno", "valor"),
        ("Transfer-Encoding", "chunked"), ("Content-Length", "5"),
        ("Upgrade", "websocket"), ("TE", "trailers"), ("User-Agent", "curl"),
    ]:
        headers[clave] = valor

    reenviados = {k.lower() for k in _headers_para_reenviar(headers)}

    assert "proxy-authorization" not in reenviados
    for hop in ("connection", "keep-alive", "upgrade", "te", "transfer-encoding"):
        assert hop not in reenviados
    # lo que Connection listaba también es de este salto
    assert "x-interno" not in reenviados
    # y lo normal pasa
    assert "user-agent" in reenviados and "host" in reenviados


def test_no_se_reenvian_content_length_y_transfer_encoding_juntos():
    """Es la receta clásica del request smuggling: cada intermediario elige
    uno distinto para saber dónde termina el cuerpo."""
    from email.message import Message

    headers = Message()
    headers["Transfer-Encoding"] = "chunked"
    headers["Content-Length"] = "5"

    reenviados = {k.lower() for k in _headers_para_reenviar(headers)}

    assert "transfer-encoding" not in reenviados
    assert "content-length" not in reenviados


# ================= datos y concurrencia =================


def test_la_lista_de_rangos_se_publica_de_una_sola_vez(tmp_path):
    """Se publicaba en dos asignaciones, así que un hilo que atendiera una
    conexión entre medio veía los inicios nuevos con los fines viejos: o un
    IndexError, o -peor, porque es silencioso- un veredicto sacado del rango
    equivocado."""
    from secureproxy.ip_ranges import IPRangeBlocklist

    archivo = tmp_path / "r.txt"
    archivo.write_text("1.2.3.0/24\n", encoding="utf-8")
    lista = IPRangeBlocklist(str(archivo))

    # el estado vive en un solo atributo, así que no hay estado intermedio
    assert isinstance(lista._rangos, tuple)
    assert lista.is_blocked("1.2.3.4") is True
    assert lista.is_blocked("9.9.9.9") is False


def test_el_firewall_apagado_no_da_por_pedido_lo_que_no_pidio():
    """El usuario apretaba "Activar" en el panel y justamente las IPs
    reincidentes -las que lo motivaron a activarlo- nunca recibían regla,
    porque el modo apagado ya las había anotado.

    Desde la fase 2 del punto 8 el proxy no escribe reglas: le PIDE a
    SecureHIPS. Pero el bug de fondo es el mismo y el test sigue cuidándolo:
    anotar como hecho algo que no se hizo."""
    fw = FirewallManager(enabled=False)
    fw.block_ip("1.2.3.4")

    fw.enabled = True
    salida = fw.block_ip("1.2.3.4")

    assert "ya se le pidió" not in salida


def test_el_firewall_no_arma_comandos_con_lo_que_no_es_una_IP():
    fw = FirewallManager(enabled=False)

    assert "no es una IP" in fw.block_ip("-A INPUT")
    assert "no es una IP" in fw.block_ip("; rm -rf /")


def test_las_alertas_de_telegram_no_demoran_la_conexion(monkeypatch):
    """Era una llamada de red sincrónica con 5 segundos de timeout, hecha en
    el hilo que atiende la conexión y justo antes de responderle al cliente:
    con Telegram lento, cada bloqueo demoraba 5 segundos el 403."""
    from secureproxy import notifier as modulo

    def lentisimo(*args, **kwargs):
        time.sleep(3)

    monkeypatch.setattr(modulo.http_client, "post", lentisimo)
    avisos = TelegramNotifier(True, "token", "chat")

    inicio = time.time()
    avisos.send_alert("algo")
    tardo = time.time() - inicio

    assert tardo < 0.5, f"send_alert bloqueó {tardo:.2f}s"


def test_escribir_atomico_no_deja_el_archivo_a_medias(tmp_path):
    """write_text trunca primero y escribe después: hay una ventana en la
    que otro hilo lee la lista vacía, y en esa ventana pasa tráfico que
    debería bloquearse."""
    archivo = tmp_path / "lista.txt"
    archivo.write_text("viejo.com\n", encoding="utf-8")

    try:
        escribir_atomico(archivo, "x" * 10)
    finally:
        pass

    assert archivo.read_text(encoding="utf-8") == "x" * 10
    # y no quedan temporales tirados
    assert [p.name for p in tmp_path.iterdir()] == ["lista.txt"]


def test_no_se_fugan_descriptores_a_la_base(tmp_path):
    """El context manager de sqlite3 hace commit de la TRANSACCIÓN, no
    cierra la conexión. Medido antes del arreglo: 283 descriptores abiertos
    a la base después de 300 conexiones ya terminadas."""
    import os

    if not os.path.exists("/proc/self/fd"):
        pytest.skip("solo se puede contar descriptores en Linux")

    db = LoggerDB(str(tmp_path / "l.db"))
    for i in range(200):
        db.log_request("127.0.0.1", "GET", f"h{i}.test", 80, "/", False)

    abiertos = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}").endswith("l.db"):
                abiertos += 1
        except OSError:
            pass

    assert abiertos == 0, f"quedaron {abiertos} descriptores abiertos"


def test_el_modo_audit_se_ve_en_el_panel(tmp_path):
    """El modo audit registra con blocked=0 y el motivo "[AUDIT] ...", pero
    el panel filtraba por blocked=1: mostraba "todavía no se bloqueó nada"
    mientras la base acumulaba todo invisible. Y el nivel Paranoico fuerza
    audit, así que quedaba inservible."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_request("127.0.0.1", "CONNECT", "evil.test", 443, "/", False,
                   reason="[AUDIT] hubiera bloqueado: dominio en blocklist: evil.test")
    db.log_request("127.0.0.1", "CONNECT", "normal.test", 443, "/", False)

    assert [f["host"] for f in db.buscar()] == ["evil.test"]
    assert db.stats()["blocked_requests"] == 1
    assert db.bloqueos_por_motivo()[0][1] == 1


# ================= feeds =================


def test_agregar_un_dominio_desde_el_bat_no_ejecuta_codigo(tmp_path, capsys):
    """El menú interpolaba el texto del prompt DENTRO del código fuente de un
    `python -c`, y la validación corría después de que el intérprete ya
    había evaluado la expresión. El propio prompt invita a pegar, y el .bat
    se corre como administrador."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import agregar_dominio

    payload = "'+__import__('os').system('echo EJECUTADO_" + "DE_VERDAD')+'"
    codigo = agregar_dominio.main(["agregar_dominio.py", "negra", payload])
    salida = capsys.readouterr().out

    assert codigo == 1
    # el payload se ve porque se lo muestra como texto en el mensaje de
    # error; lo que NO tiene que aparecer es la SALIDA de haberlo ejecutado
    assert "EJECUTADO_DE_VERDAD" not in salida.replace(payload, "")
    assert "No pude entender" in salida


# ================= que nada de esto rompió el uso normal =================


class _Backend(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A002
        pass

    def do_GET(self):
        cuerpo = b"contenido real"
        self.send_response(200)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)


def test_el_trafico_normal_sigue_pasando(tmp_path):
    backend = HTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    engine = _motor(tmp_path, allow_internal_destinations=True)
    proxy = build_proxy_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        respuesta = requests.get(
            f"http://127.0.0.1:{backend.server_address[1]}/",
            proxies={"http": f"http://127.0.0.1:{proxy.server_address[1]}"}, timeout=10,
        )
    finally:
        proxy.shutdown()
        backend.shutdown()

    assert respuesta.status_code == 200
    assert respuesta.text == "contenido real"


def test_una_respuesta_grande_no_se_carga_entera_en_memoria(tmp_path):
    """Antes se hacía `body = response.content`: medido con 400 MB, el
    proceso pasaba de 39 MB a 593 MB de RSS, y el cliente no recibía un byte
    hasta que terminaba de bajar todo."""
    tamanio = 24 * 1024 * 1024

    class Grande(BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: A002
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(tamanio))
            self.end_headers()
            escrito = 0
            trozo = b"x" * 65536
            while escrito < tamanio:
                self.wfile.write(trozo[: min(len(trozo), tamanio - escrito)])
                escrito += len(trozo)

    backend = HTTPServer(("127.0.0.1", 0), Grande)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    engine = _motor(tmp_path, allow_internal_destinations=True)
    logger = LoggerDB(str(tmp_path / "l.db"))
    proxy = build_proxy_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        respuesta = requests.get(
            f"http://127.0.0.1:{backend.server_address[1]}/",
            proxies={"http": f"http://127.0.0.1:{proxy.server_address[1]}"},
            timeout=60, stream=True,
        )
        recibido = sum(len(p) for p in respuesta.iter_content(65536))
    finally:
        proxy.shutdown()
        backend.shutdown()

    assert recibido == tamanio
    # y el volumen quedó bien contado
    filas = logger.buscar(solo_bloqueadas=False, limit=5)
    assert any(f["bytes_in"] == tamanio for f in filas)


# --------------------------------------------------------------------------
# Las tres guardas de descarga que se probaban acá (que un feed que devuelve
# HTML no pise la lista buena, que una caída brusca de entradas tampoco, y que
# un feed sano sí se guarde) se mudaron a Secure-Intel junto con el código de
# descarga. Fase 2 del punto 8.
#
# No se perdieron: allá están más completas. Secure-Intel además detecta feeds
# CONGELADOS (200 OK con los mismos bytes durante días), que es el modo de
# falla que este proyecto no sabía ver y que se parece muchísimo a estar bien.


def test_el_proxy_ya_no_tiene_guardas_de_descarga_porque_no_descarga():
    """El test que reemplaza a los tres: lo que se sacó, se sacó entero.

    Media medida sería peor que nada: un `update_blocklist` que a veces baja y
    a veces delega es un lugar más donde puede quedar una URL vieja.
    """
    import ast

    from pathlib import Path as _P

    fuente = (_P(__file__).resolve().parent.parent / "scripts" /
              "update_blocklist.py").read_text(encoding="utf-8")
    arbol = ast.parse(fuente)
    funciones = {n.name for n in ast.walk(arbol)
                 if isinstance(n, ast.FunctionDef)}
    # Quedó una sola función, y es la que delega.
    assert funciones == {"main"}
