"""Test de integración: levanta el proxy real en un puerto de prueba y hace
pedidos a través de él contra un servidor HTTP local de prueba."""

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
