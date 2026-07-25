"""Servidor proxy HTTP/HTTPS con filtrado por inteligencia de amenazas.

Soporta:
- Métodos HTTP normales (GET, POST, etc.) reenviando el pedido con `requests`.
- El método CONNECT, para tunelizar HTTPS (no se descifra el contenido: solo
  se decide si se permite abrir el túnel según el host de destino).
"""

import select
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import requests

from .filter_engine import FilterEngine
from .firewall_rules import FirewallManager
from .logger_db import LoggerDB
from .notifier import TelegramNotifier

BUFFER_SIZE = 8192


class ProxyRequestHandler(BaseHTTPRequestHandler):
    # Estos atributos se inyectan en la clase antes de levantar el servidor
    # (ver build_proxy_server más abajo), porque BaseHTTPRequestHandler no
    # admite un __init__ custom fácilmente junto con ThreadingHTTPServer.
    filter_engine: FilterEngine
    logger_db: LoggerDB
    notifier: TelegramNotifier
    firewall: FirewallManager

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Silenciamos el logging default a stderr; ya logueamos nosotros a SQLite.
        pass

    # ---------- CONNECT (HTTPS tunneling) ----------

    def do_CONNECT(self) -> None:  # noqa: N802 (nombre requerido por BaseHTTPRequestHandler)
        start = time.time()
        host, _, port_str = self.path.partition(":")
        port = int(port_str) if port_str else 443

        decision = self.filter_engine.evaluate(host)
        duration_ms = (time.time() - start) * 1000

        if decision.blocked:
            self._handle_blocked(host, port, "CONNECT", decision, duration_ms)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.logger_db.log_request(
                self.client_address[0], "CONNECT", host, port, "-", False,
                reason=f"error de conexión: {exc}", duration_ms=duration_ms,
            )
            self.send_error(502, "Bad Gateway")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.logger_db.log_request(
            self.client_address[0], "CONNECT", host, port, "-", False, duration_ms=duration_ms,
        )
        self._relay(self.connection, remote)

    def _relay(self, client_sock: socket.socket, remote_sock: socket.socket) -> None:
        """Reenvía bytes en ambas direcciones hasta que alguno de los dos lados cierre."""
        sockets = [client_sock, remote_sock]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                closed = False
                for sock in readable:
                    other = remote_sock if sock is client_sock else client_sock
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        closed = True
                        break
                    other.sendall(data)
                if closed:
                    break
        except OSError:
            pass
        finally:
            remote_sock.close()

    # ---------- HTTP normal (GET/POST/etc.) ----------

    def _handle_http_method(self, method: str) -> None:
        start = time.time()
        parsed = urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]
        port = parsed.port or 80

        decision = self.filter_engine.evaluate(host)
        duration_ms = (time.time() - start) * 1000

        if decision.blocked:
            self._handle_blocked(host, port, method, decision, duration_ms)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else None

        forward_headers = {
            key: value for key, value in self.headers.items() if key.lower() != "proxy-connection"
        }

        try:
            response = requests.request(
                method,
                self.path,
                headers=forward_headers,
                data=body,
                timeout=15,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            self.logger_db.log_request(
                self.client_address[0], method, host, port, parsed.path, False,
                reason=f"error reenviando pedido: {exc}", duration_ms=duration_ms,
            )
            self.send_error(502, "Bad Gateway")
            return

        body = response.content
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(key, value)
        # Recalculamos Content-Length nosotros: como usamos HTTP/1.1 con
        # keep-alive, el cliente necesita un largo exacto (o chunked) para
        # saber dónde termina el cuerpo; si no, se queda esperando más datos
        # hasta el timeout.
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        self.logger_db.log_request(
            self.client_address[0], method, host, port, parsed.path, False, duration_ms=duration_ms,
        )

    def do_GET(self) -> None:  # noqa: N802
        self._handle_http_method("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle_http_method("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_http_method("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_http_method("DELETE")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_http_method("HEAD")

    # ---------- helpers ----------

    def _handle_blocked(self, host: str, port: int, method: str, decision, duration_ms: float) -> None:
        self.logger_db.log_request(
            self.client_address[0], method, host, port, "-", True,
            reason=decision.reason, duration_ms=duration_ms,
        )
        self.notifier.send_alert(f"🚫 SecureProxy bloqueó una conexión a {host}\nMotivo: {decision.reason}")
        if decision.resolved_ip:
            self.firewall.block_ip(decision.resolved_ip)


class ThreadingProxyServer(ThreadingHTTPServer):
    # ThreadingHTTPServer ya combina ThreadingMixIn + HTTPServer.
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        # Un cliente que cierra la conexión abruptamente (curl, un navegador
        # que cancela la carga, etc.) no es un error real del proxy: evitamos
        # el traceback ruidoso a stderr para esos casos puntuales.
        import sys

        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError):
            return
        super().handle_error(request, client_address)


def build_proxy_server(
    host: str,
    port: int,
    filter_engine: FilterEngine,
    logger_db: LoggerDB,
    notifier: TelegramNotifier,
    firewall: FirewallManager,
) -> ThreadingProxyServer:
    """Arma el servidor inyectando las dependencias en la clase handler."""
    handler_class = type(
        "InjectedProxyRequestHandler",
        (ProxyRequestHandler,),
        {
            "filter_engine": filter_engine,
            "logger_db": logger_db,
            "notifier": notifier,
            "firewall": firewall,
        },
    )
    return ThreadingProxyServer((host, port), handler_class)
