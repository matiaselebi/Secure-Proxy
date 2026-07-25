"""Test de integración: levanta el proxy real en un puerto de prueba y hace
pedidos a través de él contra un servidor HTTP local de prueba."""

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_proxy_server  # noqa: E402
from secureproxy.threat_intel import AbuseIPDBClient, Blocklist, TorExitNodeList  # noqa: E402


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
    filter_engine = FilterEngine(
        blocklist=blocklist,
        abuseipdb_client=AbuseIPDBClient(api_key="", cache_ttl=60),
        tor_list=TorExitNodeList(cache_ttl=60),
        abuseipdb_min_score=50,
        check_tor_exit_nodes=False,
    )
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    notifier = TelegramNotifier(enabled=False, bot_token="", chat_id="")
    firewall = FirewallManager(enabled=False)

    server = build_proxy_server("127.0.0.1", 0, filter_engine, logger_db, notifier, firewall)
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
