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
from urllib.parse import parse_qs, quote, urlsplit

import requests

from .filter_engine import FilterEngine
from .firewall_rules import FirewallManager
from .logger_db import LoggerDB
from .notifier import TelegramNotifier
from .threat_intel import Allowlist

BUFFER_SIZE = 8192


class ProxyRequestHandler(BaseHTTPRequestHandler):
    # Estos atributos se inyectan en la clase antes de levantar el servidor
    # (ver build_proxy_server más abajo), porque BaseHTTPRequestHandler no
    # admite un __init__ custom fácilmente junto con ThreadingHTTPServer.
    filter_engine: FilterEngine
    logger_db: LoggerDB
    notifier: TelegramNotifier
    firewall: FirewallManager
    allowlist: Allowlist

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
                # terminaría pidiéndose a sí mismo en bucle - muy notorio al
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
        parsed_path = urlsplit(self.path)
        clean_path = parsed_path.path.rstrip("/")
        dashboard_routes = {
            "/dashboard": self._serve_dashboard,
            "/allow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=True),
            "/unallow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=False),
            "/blockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=True),
            "/unblockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=False),
            "/clear-cache": self._handle_clear_cache,
        }
        if clean_path in dashboard_routes:
            dashboard_routes[clean_path]()
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

    def _redirect_to_dashboard(self) -> None:
        """Respuesta común para las acciones del dashboard (permitir/quitar/
        bloquear/borrar cache): redirige de vuelta y cierra la conexión.

        Cerrarla explícitamente (en vez de mantener keep-alive) evita el
        cuelgue que reportó el usuario: si el navegador deja la pestaña del
        dashboard en segundo plano, el refresco automático puede demorarse
        más que el timeout del socket, y el navegador termina intentando
        reusar una conexión que el servidor ya cerró por inactividad. Al
        forzar una conexión nueva en cada acción/refresco, ese problema no
        puede pasar."""
        self.send_response(303)
        self.send_header("Location", "/dashboard")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _handle_list_edit(self, target_list, query_string: str, add: bool) -> None:
        """Endpoint común para agregar/quitar un dominio de una lista
        (allowlist o blocklist manual). Pensado para uso local únicamente
        (no valida quién llama, ya que el dashboard solo escucha en loopback)."""
        params = parse_qs(query_string)
        domain = (params.get("domain") or [""])[0].strip()
        if domain:
            if add:
                target_list.add_and_reload(domain)
            else:
                target_list.remove_and_reload(domain)
        self._redirect_to_dashboard()

    def _handle_clear_cache(self) -> None:
        """Endpoint del botón "Borrar cache": vacía el cache (en memoria y
        persistente) de resultados de AbuseIPDB."""
        self.filter_engine.abuseipdb_client.clear_cache()
        self._redirect_to_dashboard()

    @staticmethod
    def _render_editable_list(items: list[str], remove_endpoint: str) -> str:
        if not items:
            return "<p class='empty'>No hay dominios cargados todavía.</p>"
        rows = "".join(
            f"<tr><td>{html_lib.escape(domain)}</td>"
            f"<td><a class='danger' href=\"{remove_endpoint}?domain={quote(domain)}\" "
            f"onclick=\"return confirm('¿Quitar ' + '{html_lib.escape(domain)}' + '?')\">Quitar</a></td></tr>"
            for domain in items
        )
        return f"<table><tr><th>Dominio</th><th>Acción</th></tr>{rows}</table>"

    def _serve_dashboard(self) -> None:
        stats = self.logger_db.stats()
        total = stats["total_requests"]
        blocked = stats["blocked_requests"]
        block_rate = (blocked / total * 100) if total else 0.0

        persistent_cache = self.filter_engine.abuseipdb_client.persistent_cache
        cache_entries = persistent_cache.count() if persistent_cache is not None else 0

        rows = self.logger_db.recent_blocked(limit=25)
        if rows:
            rows_html = "".join(
                f"<tr><td>{html_lib.escape(str(ts))}</td>"
                f"<td>{html_lib.escape(str(host))}</td>"
                f"<td>{html_lib.escape(str(reason))}</td>"
                f"<td><a href=\"/allow?domain={quote(str(host))}\" "
                f"onclick=\"return confirm('¿Permitir siempre ' + '{html_lib.escape(str(host))}' + '?')\">"
                f"Permitir</a></td></tr>"
                for ts, host, reason in rows
            )
        else:
            rows_html = "<tr><td colspan='4'>Todavía no se bloqueó ninguna conexión.</td></tr>"

        allowlist_html = self._render_editable_list(
            self.filter_engine.allowlist.manual_entries(), "/unallow"
        )
        blocklist_html = self._render_editable_list(
            self.filter_engine.blocklist.manual_entries(), "/unblockdomain"
        )

        page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>SecureProxy - Dashboard</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; }}
  .subtitle {{ color:#9aa0a6; font-size:0.85rem; margin-top:0; }}
  .stats {{ display:flex; gap:1.25rem; margin: 1.5rem 0; flex-wrap: wrap; align-items: stretch; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:1rem 1.5rem; min-width:140px; }}
  .card .value {{ font-size:1.8rem; font-weight:600; }}
  .card .label {{ color:#9aa0a6; font-size:0.85rem; }}
  .card.action {{ display:flex; align-items:center; justify-content:center; }}
  table {{ width:100%; border-collapse: collapse; margin-top:0.5rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #2a2e37; font-size:0.85rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
  .empty {{ color:#9aa0a6; font-size:0.85rem; }}
  a {{ color:#7fb2ff; }}
  a.danger {{ color:#ff8a8a; }}
  .tabs {{ display:flex; gap:0.5rem; margin-top:1.5rem; border-bottom:1px solid #2a2e37; }}
  .tab-btn {{ background:none; border:none; color:#9aa0a6; font-size:0.9rem; padding:0.6rem 1rem; cursor:pointer; border-bottom:2px solid transparent; }}
  .tab-btn.active {{ color:#e6e6e6; border-bottom:2px solid #7fb2ff; }}
  .tab-panel {{ display:none; padding-top:1rem; }}
  .tab-panel.active {{ display:block; }}
  .add-form {{ display:flex; gap:0.5rem; margin-bottom:1rem; }}
  .add-form input[type=text] {{ flex:1; background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; }}
  .add-form button, button.danger-btn {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; }}
  button.danger-btn {{ background:#3a1f22; color:#ff8a8a; }}
</style>
</head>
<body>
  <h1>SecureProxy</h1>
  <p class="subtitle">Panel de control - se actualiza solo cada 5 segundos</p>
  <div class="stats">
    <div class="card"><div class="value">{total}</div><div class="label">Conexiones totales</div></div>
    <div class="card"><div class="value">{blocked}</div><div class="label">Bloqueadas</div></div>
    <div class="card"><div class="value">{block_rate:.1f}%</div><div class="label">Tasa de bloqueo</div></div>
    <div class="card"><div class="value">{cache_entries}</div><div class="label">IPs en cache (AbuseIPDB)</div></div>
    <div class="card action">
      <form method="get" action="/clear-cache" onsubmit="return confirm('¿Borrar el cache de reputación de IPs?')">
        <button type="submit" class="danger-btn">Borrar cache</button>
      </form>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="bloqueos" onclick="showTab('bloqueos', this)">Bloqueos</button>
    <button class="tab-btn" data-tab="blanca" onclick="showTab('blanca', this)">Lista blanca</button>
    <button class="tab-btn" data-tab="negra" onclick="showTab('negra', this)">Lista negra (manual)</button>
  </div>

  <div id="tab-bloqueos" class="tab-panel active">
    <h2>Últimos bloqueos</h2>
    <table>
      <tr><th>Fecha/hora (UTC)</th><th>Host</th><th>Motivo</th><th>Acción</th></tr>
      {rows_html}
    </table>
  </div>

  <div id="tab-blanca" class="tab-panel">
    <h2>Lista blanca</h2>
    <p class="empty">Un dominio acá gana por sobre blocklist, TOR y AbuseIPDB.</p>
    <form class="add-form" method="get" action="/allow">
      <input type="text" name="domain" placeholder="ejemplo.com" required>
      <button type="submit">Agregar</button>
    </form>
    {allowlist_html}
  </div>

  <div id="tab-negra" class="tab-panel">
    <h2>Lista negra (manual)</h2>
    <p class="empty">Solo la lista manual (data/blocklist.txt). Lo generado por
    URLhaus/OpenPhish/Feodo Tracker no se administra desde acá.</p>
    <form class="add-form" method="get" action="/blockdomain">
      <input type="text" name="domain" placeholder="ejemplo.com" required>
      <button type="submit">Agregar</button>
    </form>
    {blocklist_html}
  </div>

<script>
var TAB_STORAGE_KEY = 'secureproxy_dashboard_tab';
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(function(el) {{ el.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(el) {{ el.classList.remove('active'); }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  try {{ localStorage.setItem(TAB_STORAGE_KEY, name); }} catch (e) {{ /* sin soporte de localStorage: no pasa nada */ }}
}}
(function() {{
  // Restaura la pestaña que se estaba mirando antes del refresco automático
  // de cada 5 segundos, en vez de volver siempre a "Bloqueos".
  var saved = null;
  try {{ saved = localStorage.getItem(TAB_STORAGE_KEY); }} catch (e) {{ /* nada */ }}
  if (saved) {{
    var btn = document.querySelector('.tab-btn[data-tab="' + saved + '"]');
    if (btn) {{ showTab(saved, btn); }}
  }}
}})();
</script>
</body>
</html>"""

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

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
    allowlist: Allowlist,
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
            "allowlist": allowlist,
        },
    )
    return ThreadingProxyServer((host, port), handler_class)
