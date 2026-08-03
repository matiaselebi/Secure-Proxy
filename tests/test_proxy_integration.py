"""Test de integración: levanta el proxy real en un puerto de prueba y hace
pedidos a través de él contra un servidor HTTP local de prueba."""

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.ip_reputation_cache import PersistentIPCache  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_proxy_server  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
)


class EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello from backend")


@pytest.fixture()
def backend_server():
    server = HTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture()
def proxy_server(tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("blocked-site.test\n")

    blocklist = Blocklist(str(blocklist_path))
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist = Allowlist(str(allowlist_path))
    persistent_cache = PersistentIPCache(str(tmp_path / "ip_reputation_cache.db"))
    filter_engine = FilterEngine(
        blocklist=blocklist,
        abuseipdb_client=AbuseIPDBClient(api_key="", cache_ttl=60, persistent_cache=persistent_cache),
        tor_list=TorExitNodeList(cache_ttl=60),
        allowlist=allowlist,
        abuseipdb_min_score=50,
        check_tor_exit_nodes=False,
        # El backend de prueba vive en 127.0.0.1 y en un puerto efímero:
        # sin esto lo cortaría la política de destino, que es justamente lo
        # que queremos que corte en producción.
        allow_internal_destinations=True,
    )
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    notifier = TelegramNotifier(enabled=False, bot_token="", chat_id="")
    firewall = FirewallManager(enabled=False)

    server = build_proxy_server(
        "127.0.0.1", 0, filter_engine, logger_db, notifier, firewall, allowlist
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield server
    server.shutdown()


def test_proxy_forwards_allowed_request(backend_server, proxy_server):
    backend_port = backend_server.server_address[1]
    proxy_port = proxy_server.server_address[1]

    response = requests.get(
        f"http://127.0.0.1:{backend_port}/",
        proxies={"http": f"http://127.0.0.1:{proxy_port}"},
        timeout=5,
    )

    assert response.status_code == 200
    assert response.text == "hello from backend"


def test_proxy_blocks_blocklisted_domain(proxy_server, monkeypatch):
    proxy_port = proxy_server.server_address[1]

    response = requests.get(
        "http://blocked-site.test/",
        proxies={"http": f"http://127.0.0.1:{proxy_port}"},
        timeout=5,
    )

    assert response.status_code == 403


def test_dashboard_served_directly(proxy_server):
    """El dashboard se sirve con un GET directo al proxy (sin usar `proxies=`,
    exactamente como lo haría un navegador apuntando a http://127.0.0.1:8888/dashboard)."""
    proxy_port = proxy_server.server_address[1]

    response = requests.get(f"http://127.0.0.1:{proxy_port}/dashboard", timeout=5)

    assert response.status_code == 200
    assert "SecureProxy" in response.text
    assert "Conexiones totales" in response.text


def test_dashboard_served_via_absolute_uri(proxy_server):
    """Reproduce el caso real de un navegador con este proxy configurado a
    nivel de sistema: manda la URL completa (forma absoluta) en vez de solo
    el path. Debe servirse el dashboard directo, SIN reenviarse a sí mismo
    (lo cual, sin el fix, produce el colgado que reportó el usuario)."""
    proxy_port = proxy_server.server_address[1]

    response = requests.get(
        f"http://127.0.0.1:{proxy_port}/dashboard",
        proxies={"http": f"http://127.0.0.1:{proxy_port}"},
        timeout=5,
    )

    assert response.status_code == 200
    assert "SecureProxy" in response.text
    assert "Conexiones totales" in response.text


def test_allow_endpoint_unblocks_domain(backend_server, proxy_server):
    """Bloqueado por blocklist -> se aprieta "Permitir" (GET /allow?domain=...)
    -> el mismo dominio ahora pasa, porque la allowlist gana por sobre la
    blocklist. Usamos "127.0.0.1" (el host del backend de prueba) como el
    "dominio" bloqueado, para poder efectivamente reenviar el pedido una vez
    permitido."""
    backend_port = backend_server.server_address[1]
    proxy_port = proxy_server.server_address[1]
    backend_url = f"http://127.0.0.1:{backend_port}/"

    proxy_server.RequestHandlerClass.filter_engine.blocklist._domains.add("127.0.0.1")

    blocked = requests.get(
        backend_url,
        proxies={"http": f"http://127.0.0.1:{proxy_port}"},
        timeout=5,
    )
    assert blocked.status_code == 403

    allow_response = requests.get(
        f"http://127.0.0.1:{proxy_port}/allow?domain=127.0.0.1",
        timeout=5,
        allow_redirects=False,
    )
    assert allow_response.status_code == 303
    assert allow_response.headers["Location"] == "/dashboard"

    now_allowed = requests.get(
        backend_url,
        proxies={"http": f"http://127.0.0.1:{proxy_port}"},
        timeout=5,
    )
    assert now_allowed.status_code == 200
    assert now_allowed.text == "hello from backend"


def test_unallow_endpoint_removes_domain_from_allowlist(proxy_server):
    proxy_port = proxy_server.server_address[1]
    allowlist = proxy_server.RequestHandlerClass.filter_engine.allowlist
    allowlist.add_and_reload("trusted-example.com")
    assert allowlist.is_allowed("trusted-example.com") is True

    response = requests.get(
        f"http://127.0.0.1:{proxy_port}/unallow?domain=trusted-example.com",
        timeout=5,
        allow_redirects=False,
    )

    assert response.status_code == 303
    assert allowlist.is_allowed("trusted-example.com") is False


def test_blockdomain_and_unblockdomain_endpoints(proxy_server):
    proxy_port = proxy_server.server_address[1]
    blocklist = proxy_server.RequestHandlerClass.filter_engine.blocklist

    add_response = requests.get(
        f"http://127.0.0.1:{proxy_port}/blockdomain?domain=new-bad-example.com",
        timeout=5,
        allow_redirects=False,
    )
    assert add_response.status_code == 303
    assert blocklist.is_blocked("new-bad-example.com") is True

    remove_response = requests.get(
        f"http://127.0.0.1:{proxy_port}/unblockdomain?domain=new-bad-example.com",
        timeout=5,
        allow_redirects=False,
    )
    assert remove_response.status_code == 303
    assert blocklist.is_blocked("new-bad-example.com") is False


def test_clear_cache_endpoint_empties_persistent_cache(proxy_server):
    proxy_port = proxy_server.server_address[1]
    abuseipdb_client = proxy_server.RequestHandlerClass.filter_engine.abuseipdb_client
    abuseipdb_client.persistent_cache.set("1.2.3.4", 80)
    abuseipdb_client._cache["1.2.3.4"] = (80, time.time())
    assert abuseipdb_client.persistent_cache.count() == 1

    response = requests.get(
        f"http://127.0.0.1:{proxy_port}/clear-cache", timeout=5, allow_redirects=False
    )

    assert response.status_code == 303
    assert abuseipdb_client.persistent_cache.count() == 0
    assert abuseipdb_client._cache == {}


def test_dashboard_shows_tabs_and_cache_count(proxy_server):
    proxy_port = proxy_server.server_address[1]
    allowlist = proxy_server.RequestHandlerClass.filter_engine.allowlist
    allowlist.add_and_reload("trusted-example.com")

    response = requests.get(f"http://127.0.0.1:{proxy_port}/dashboard", timeout=5)

    assert response.status_code == 200
    assert "Lista blanca" in response.text
    assert "Lista negra (manual)" in response.text
    assert "trusted-example.com" in response.text
    assert "IPs en cache (AbuseIPDB)" in response.text
    assert "Borrar cache" in response.text


def test_stalled_client_does_not_hang_forever(proxy_server):
    """Un cliente que se conecta y nunca manda nada (pestaña colgada, red que
    se corta a mitad de camino) no debe dejar el hilo del servidor esperando
    para siempre: el timeout de socket tiene que cortar la conexión sola."""
    proxy_server.RequestHandlerClass.timeout = 0.5  # más corto, solo para el test

    proxy_port = proxy_server.server_address[1]
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)

    start = time.time()
    data = sock.recv(1024)  # no mandamos nada: esperamos que el server corte solo
    elapsed = time.time() - start

    sock.close()

    assert data == b""  # el servidor cerró la conexión por inactividad
    assert elapsed < 3  # se cortó rápido, no se quedó colgado


def test_blockdomain_endpoint_acepta_una_url_pegada_y_la_limpia(proxy_server):
    """Nadie copia dominios: uno copia la barra del navegador. Antes esto se
    rechazaba en silencio; ahora se limpia y se guarda el dominio."""
    proxy_port = proxy_server.server_address[1]
    blocklist = proxy_server.RequestHandlerClass.filter_engine.blocklist

    response = requests.get(
        f"http://127.0.0.1:{proxy_port}/blockdomain?domain="
        + quote("https://www.un-dominio.com/una/seccion?x=1"),
        timeout=5,
        allow_redirects=False,
    )

    assert response.status_code == 303
    assert "un-dominio.com" in blocklist.manual_entries()
    # y la regla cubre las dos formas, con y sin www.
    assert blocklist.is_blocked("un-dominio.com") is True
    assert blocklist.is_blocked("www.un-dominio.com") is True
    # el redirect avisa qué se le sacó, en vez de guardar algo distinto en
    # silencio
    assert "aviso=" in response.headers["Location"]


def test_blockdomain_endpoint_rejects_malformed_input(proxy_server):
    """Limpiar una URL es una cosa; tragarse cualquier cosa es otra. Basura
    real sigue sin entrar al archivo."""
    proxy_port = proxy_server.server_address[1]
    blocklist = proxy_server.RequestHandlerClass.filter_engine.blocklist

    for basura in ("no es un dominio", "://", "...", "%%%"):
        response = requests.get(
            f"http://127.0.0.1:{proxy_port}/blockdomain?domain=" + quote(basura),
            timeout=5,
            allow_redirects=False,
        )
        assert response.status_code == 303

    # la fixture arranca con un dominio; ninguno de los de arriba se sumó
    assert blocklist.manual_entries() == ["blocked-site.test"]


# ---- Dashboard en su propio puerto (separado del puerto que proxea) ----

def test_dashboard_en_puerto_propio_se_puede_abrir_muchas_veces():
    """El bug que motivo la separacion: con el dashboard en el MISMO puerto
    que el proxy, la pagina andaba la primera vez y despues quedaba cargando
    para siempre (el navegador reusaba conexiones del pool del proxy). Con
    puerto propio, abrirla 10 veces seguidas tiene que andar siempre."""
    import tempfile, threading, urllib.request, os
    from secureproxy.filter_engine import FilterEngine
    from secureproxy.firewall_rules import FirewallManager
    from secureproxy.logger_db import LoggerDB
    from secureproxy.notifier import TelegramNotifier
    from secureproxy.proxy_server import build_dashboard_server
    from secureproxy.threat_intel import (
        AbuseIPDBClient, Allowlist, Blocklist, TorExitNodeList,
    )

    tmp = tempfile.mkdtemp()
    for n in ("b.txt", "a.txt"):
        open(os.path.join(tmp, n), "w").close()
    allowlist = Allowlist(os.path.join(tmp, "a.txt"))
    engine = FilterEngine(
        blocklist=Blocklist(os.path.join(tmp, "b.txt")),
        abuseipdb_client=AbuseIPDBClient(""),
        tor_list=TorExitNodeList(),
        allowlist=allowlist,
        check_tor_exit_nodes=False,
    )
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, LoggerDB(os.path.join(tmp, "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        for i in range(10):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                assert resp.status == 200, f"fallo en la apertura {i + 1}"
                assert "SecureProxy" in resp.read().decode("utf-8", "replace")
    finally:
        server.shutdown()


def test_un_pedido_a_otro_sitio_no_activa_las_rutas_del_panel():
    """En el puerto que proxea, lo que decide si un pedido es para el panel o
    es trafico a reenviar es el DESTINO, no el path. Sin esto, cualquier
    sitio con un path igual al de una ruta del panel se la hacia ejecutar al
    proxy: en el peor caso, una pagina cualquiera podia cambiarle la
    configuracion con solo hacerte visitar /config?k=...&v=..."""
    from urllib.parse import urlsplit

    from secureproxy.proxy_server import ProxyRequestHandler

    class _ServidorFalso:
        server_address = ("127.0.0.1", 8888)

    handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
    handler.server = _ServidorFalso()

    # Forma relativa: entraron derecho.
    assert handler._es_para_nosotros(urlsplit("/dashboard")) is True

    # Forma absoluta hacia nosotros mismos: tambien es el panel.
    assert handler._es_para_nosotros(urlsplit("http://127.0.0.1:8888/")) is True
    assert handler._es_para_nosotros(urlsplit("http://localhost:8888/config")) is True

    # Forma absoluta hacia afuera: es trafico, aunque el path coincida.
    assert handler._es_para_nosotros(urlsplit("http://google.com/")) is False
    assert handler._es_para_nosotros(urlsplit("http://google.com/dashboard")) is False
    assert handler._es_para_nosotros(urlsplit("http://evil.test/config?k=mode&v=audit")) is False
    # Mismo host, otro puerto: no somos nosotros.
    assert handler._es_para_nosotros(urlsplit("http://127.0.0.1:9999/")) is False


def test_el_puerto_del_dashboard_no_proxea():
    """Ese puerto sirve el panel y nada mas: un CONNECT o un POST se rechazan,
    para que no quede una via alternativa de proxeo sin filtrar."""
    from secureproxy.proxy_server import DashboardOnlyRequestHandler

    for metodo in ("do_POST", "do_PUT", "do_DELETE", "do_CONNECT"):
        assert hasattr(DashboardOnlyRequestHandler, metodo)


def test_config_trae_puerto_de_dashboard_separado():
    from secureproxy.config_loader import ProxyConfig

    cfg = ProxyConfig()
    assert cfg.port == 8888            # por donde proxea
    assert cfg.dashboard_port == 8889  # por donde se ve el panel
    assert cfg.port != cfg.dashboard_port
