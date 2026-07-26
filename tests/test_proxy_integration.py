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


def test_blockdomain_endpoint_rejects_malformed_input(proxy_server):
    """Un valor pegado por error (URL completa, con espacios, etc.) no debe
    terminar escrito en el archivo de blocklist."""
    proxy_port = proxy_server.server_address[1]
    blocklist = proxy_server.RequestHandlerClass.filter_engine.blocklist

    response = requests.get(
        f"http://127.0.0.1:{proxy_port}/blockdomain?domain=" + quote("http://not-a-domain.com/x"),
        timeout=5,
        allow_redirects=False,
    )

    assert response.status_code == 303
    assert blocklist.is_blocked("not-a-domain.com") is False
    assert "not-a-domain.com" not in blocklist.manual_entries()
