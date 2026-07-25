"""Servidor proxy HTTP/HTTPS con filtrado por inteligencia de amenazas.

Soporta:
- Métodos HTTP normales (GET, POST, etc.) reenviando el pedido con `requests`.
- El método CONNECT, para tunelizar HTTPS (no se descifra el contenido: solo
  se decide si se permite abrir el túnel según el host de destino).
"""

import html as html_lib
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

    # Tiempo máximo de inactividad esperando datos del cliente (leer la línea
    # de pedido, headers, etc). Sin esto, un cliente que se cuelga a mitad de
    # camino (pestaña cerrada de golpe, red que se corta) deja el hilo
    # esperando para siempre. No aplica al túnel CONNECT ya establecido: ese
    # tiene su propia lógica de inactividad en _relay (ver do_CONNECT).
    timeout = 5

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

        # A partir de acá el socket pasa a ser un túnel de bytes crudos (TLS),
        # potencialmente de larga duración (streaming, descargas, WebSockets).
        # Le sacamos el timeout de 30s de la fase de headers: la inactividad
        # del túnel la maneja _relay con su propio límite de 60s sin tráfico
        # en NINGUNA dirección (no 30s desde la última lectura puntual).
        self.connection.settimeout(None)
        # No reutilizamos esta conexión para más pedidos HTTP después del
        # túnel: evita que el parser de keep-alive intente leer una nueva
        # request-line sobre un socket que ya se usó para bytes de TLS.
        self.close_connection = True

        self._relay(self.connection, remote)

    def _relay(self, client_sock: socket.socket, remote_sock: socket.socket) -> None:
        """Reenvía bytes en ambas direcciones hasta que alguno de los dos lados
        cierre, o hasta que pasen 60s sin tráfico en ninguna dirección."""
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
            try:
                remote_sock.close()
            except OSError:
                pass
            try:
                client_sock.close()
            except OSError:
                pass

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
                # Fuerza a 'requests' a NO usar ningún proxy del sistema/entorno
                # para esta conexión saliente. Sin esto, si el sistema operativo
                # tiene configurado este mismo proxy como proxy general (que es
                # justamente lo que hace SecureProxy.bat), el proceso del proxy
                # terminaría pidiéndose a sí mismo en bucle — muy notorio al
                # entrar directo a /dashboard, que no pasa por el túnel CONNECT.
                proxies={"http": None, "https": None},
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
        # El dashboard se reconoce por el path, sea que el pedido llegue en
        # forma relativa ("/dashboard", entrando directo) o absoluta
        # ("http://127.0.0.1:8888/dashboard", que es como lo manda un
        # navegador que tiene este mismo proxy configurado a nivel de
        # sistema). En ambos casos se sirve localmente, sin reenviar nada.
        if urlsplit(self.path).path.rstrip("/") == "/dashboard":
            self._serve_dashboard()
            return
        self._handle_http_method("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle_http_method("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_http_method("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_http_method("DELETE")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_http_method("HEAD")

    # ---------- dashboard ----------

    def _serve_dashboard(self) -> None:
        stats = self.logger_db.stats()
        total = stats["total_requests"]
        blocked = stats["blocked_requests"]
        block_rate = (blocked / total * 100) if total else 0.0

        rows = self.logger_db.recent_blocked(limit=25)
        if rows:
            rows_html = "".join(
                f"<tr><td>{html_lib.escape(str(ts))}</td>"
                f"<td>{html_lib.escape(str(host))}</td>"
                f"<td>{html_lib.escape(str(reason))}</td></tr>"
                for ts, host, reason in rows
            )
        else:
            rows_html = "<tr><td colspan='3'>Todavía no se bloqueó ninguna conexión.</td></tr>"

        page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>SecureProxy — Dashboard</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  .subtitle {{ color:#9aa0a6; font-size:0.85rem; margin-top:0; }}
  .stats {{ display:flex; gap:1.25rem; margin: 1.5rem 0; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:1rem 1.5rem; min-width:140px; }}
  .card .value {{ font-size:1.8rem; font-weight:600; }}
  .card .label {{ color:#9aa0a6; font-size:0.85rem; }}
  table {{ width:100%; border-collapse: collapse; margin-top:0.5rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #2a2e37; font-size:0.85rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
</style>
</head>
<body>
  <h1>SecureProxy</h1>
  <p class="subtitle">Panel de bloqueos — se actualiza solo cada 5 segundos</p>
  <div class="stats">
    <div class="card"><div class="value">{total}</div><div class="label">Conexiones totales</div></div>
    <div class="card"><div class="value">{blocked}</div><div class="label">Bloqueadas</div></div>
    <div class="card"><div class="value">{block_rate:.1f}%</div><div class="label">Tasa de bloqueo</div></div>
  </div>
  <h2>Últimos bloqueos</h2>
  <table>
    <tr><th>Fecha/hora (UTC)</th><th>Host</th><th>Motivo</th></tr>
    {rows_html}
  </table>
</body>
</html>"""

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
