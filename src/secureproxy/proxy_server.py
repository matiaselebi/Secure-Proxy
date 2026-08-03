"""Servidor proxy HTTP/HTTPS con filtrado por inteligencia de amenazas.

Soporta:
- Métodos HTTP normales (GET, POST, etc.) reenviando el pedido con `requests`.
- El método CONNECT, para tunelizar HTTPS (no se descifra el contenido: solo
  se decide si se permite abrir el túnel según el host de destino).
"""

import csv
import html as html_lib
import io
import ipaddress
import json
import select
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

import requests

from . import feeds_status
from .filter_engine import FilterDecision, FilterEngine
from .firewall_rules import FirewallManager
from .logger_db import LoggerDB
from .notifier import TelegramNotifier
from .threat_intel import Allowlist, resolve_host_to_ip
from .validation import (
    is_valid_domain,
    limpiar_para_mostrar,
    normalizar_dominio,
    normalizar_host_de_trafico,
)

BUFFER_SIZE = 8192

# Tope del cuerpo que se acepta en un pedido HTTP normal (no aplica al túnel
# CONNECT, que va en streaming). 64 MB es holgado para cualquier subida real
# por HTTP plano y a la vez impide que un "Content-Length: 3000000000"
# reserve gigabytes de una.
MAX_BODY = 64 * 1024 * 1024

# Puertos a los que tiene sentido abrir un túnel. Un proxy web que deja
# tunelizar a cualquier puerto es un pivote de red: sirve para llegar a SSH,
# SMB o RDP de la propia máquina o de la LAN, con el agravante de que en el
# panel se ve como una "conexión permitida" más.
PUERTOS_PERMITIDOS = frozenset({80, 443, 8080, 8443})

# Lo último que ve el navegador antes de que el proceso cierre. Es una página
# suelta y no una redirección al panel a propósito: el panel ya no va a estar
# ahí para contestar, y un refresco automático daría "no se puede conectar",
# que parece un error cuando en realidad salió todo bien.
PAGINA_DE_APAGADO = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>SecureProxy apagado</title>
<style>
  body { background:#0f1419; color:#e6edf3; font-family:system-ui, sans-serif;
         display:flex; align-items:center; justify-content:center;
         min-height:100vh; margin:0; }
  .caja { max-width:36rem; padding:2rem; text-align:center; }
  h1 { color:#f0883e; margin:0 0 0.6rem 0; }
  p { color:#8b949e; line-height:1.6; }
  code { background:#161b22; border:1px solid #30363d; border-radius:6px;
         padding:0.15rem 0.4rem; color:#e6edf3; white-space:nowrap;
         display:inline-block; }
</style>
</head>
<body>
  <div class="caja">
    <h1>SecureProxy apagado</h1>
    <p>El proceso se cerró solo, igual que con Ctrl+C: se guardó todo y se
       borró el archivo de PID.</p>
    <p><strong>El navegador sigue apuntando al proxy.</strong> Si dejaste el
       proxy configurado en el sistema o en el navegador, sacalo o no vas a
       poder navegar hasta que lo vuelvas a levantar.</p>
    <p>Para levantarlo de nuevo: <code>python scripts/run_proxy.py</code>, o
       la opción 1 de <code>SecureProxy.bat</code>. Si corre como servicio:
       <code>sudo systemctl start secureproxy</code>.</p>
  </div>
</body>
</html>
"""


def _partir_destino(destino: str) -> tuple[str, int | None]:
    """Parte "host:puerto" del CONNECT, incluida la forma IPv6 [::1]:443.

    Devuelve (host, puerto) o (host, None) si el puerto no es un número.
    Usa rpartition y no partition porque un IPv6 literal tiene dos puntos
    adentro: partiendo por el primero, "[::1]:443" dejaba host="[".
    """
    destino = (destino or "").strip()
    if not destino:
        return "", None
    if destino.startswith("["):
        cierre = destino.find("]")
        if cierre == -1:
            return "", None
        host = destino[1:cierre]
        resto = destino[cierre + 1:]
        if not resto:
            return host, 443
        if not resto.startswith(":"):
            return "", None
        cola = resto[1:]
    else:
        host, sep, cola = destino.rpartition(":")
        if not sep:
            return destino, 443
    if not cola:
        return host, 443
    if not cola.isdigit():
        return host, None
    puerto = int(cola)
    if not (0 < puerto < 65536):
        return host, None
    return host, puerto


# Cabeceras que valen solo entre dos saltos y NO deben cruzar al siguiente
# (RFC 9110). Antes se filtraba únicamente Proxy-Connection.
HEADERS_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
})


def _headers_para_reenviar(headers) -> dict:
    """Los headers del cliente, listos para mandarle al destino.

    Se sacan tres cosas y cada una por su motivo:

    - Las cabeceras **hop-by-hop**: por definición son entre el cliente y el
      proxy, no para el destino. `Proxy-Authorization` es la peor de todas:
      es la credencial del proxy y filtrarla al sitio de destino es
      entregarle una contraseña que no es suya.
    - Lo que liste `Connection:`, porque el RFC dice que esas cabeceras
      también son de este salto y antes se ignoraba por completo.
    - **`Transfer-Encoding` junto con `Content-Length`**: mandar los dos a la
      vez es la receta clásica del request smuggling, porque cada
      intermediario elige uno distinto para saber dónde termina el cuerpo.
      Acá el largo se recalcula solo, así que no hay motivo para propagarlos.
    """
    listados = set()
    conexion = headers.get("Connection") or ""
    for pieza in conexion.split(","):
        pieza = pieza.strip().lower()
        if pieza and pieza not in ("close", "keep-alive"):
            listados.add(pieza)

    return {
        clave: valor
        for clave, valor in headers.items()
        if clave.lower() not in HEADERS_HOP_BY_HOP
        and clave.lower() not in listados
        and clave.lower() != "content-length"
    }


def _es_destino_interno(host: str) -> bool:
    """¿Este destino es la propia máquina, la red local o un servicio de
    metadatos de nube?

    Solo mira IPs literales a propósito: un nombre se resuelve más adelante
    y ahí se vuelve a chequear con la IP real, que es donde de verdad
    importa (un nombre puede apuntar a 127.0.0.1 sin que se note).
    """
    try:
        direccion = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        direccion.is_loopback
        or direccion.is_private
        or direccion.is_link_local
        or direccion.is_reserved
        or direccion.is_multicast
        or direccion.is_unspecified
    )


def formatear_fecha(iso: str) -> str:
    """Convierte el timestamp guardado a algo legible y EN HORA LOCAL.

    En la base se guarda en UTC y en formato ISO completo
    ("2026-07-27T00:09:15.704172+00:00") porque así se ordena bien y no
    depende de la zona horaria de la máquina. Pero mostrarlo tal cual en el
    panel es ilegible -y encima confunde, porque no es la hora que marca tu
    reloj-. Acá se pasa a la hora local y a "27/07/2026 21:09:15".
    """
    try:
        momento = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return str(iso)
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.astimezone().strftime("%d/%m/%Y %H:%M:%S")


def _intervalo_legible(segundos: float) -> str:
    """"cada 60 segundos" o "cada 5 minutos", según cuál se lea mejor."""
    if segundos < 90:
        return f"{segundos:.0f} segundos"
    if segundos < 5400:
        return f"{segundos / 60:.1f} minutos"
    return f"{segundos / 3600:.1f} horas"


def formatear_bytes(cantidad) -> str:
    """Bytes en algo legible. "1.4 MB" se entiende, "1468006" no."""
    try:
        valor = float(cantidad or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unidad in ("B", "KB", "MB", "GB"):
        if valor < 1024 or unidad == "GB":
            if unidad == "B":
                return f"{int(valor)} B"
            return f"{valor:.1f} {unidad}"
        valor /= 1024
    return f"{valor:.1f} GB"


def hora_local(clave_utc: str) -> str:
    """Pasa la clave horaria del agrupamiento ("2026-07-29T05") a la hora
    local, mostrando solo la hora.

    Dos cosas se arreglan acá. Una, que se veía la fecha al lado, que sobra
    en un gráfico de las últimas 24 horas. La otra, más importante: el
    agrupamiento se hace sobre el timestamp guardado, que está en UTC, así
    que las barras estaban corridas respecto de la tabla del historial, que
    sí muestra hora local. Ahora las dos hablan de lo mismo.

    Se muestra HH:00 y no HH:MM:SS porque cada barra ES una hora entera:
    los minutos y los segundos serían siempre cero y darían una idea falsa
    de precisión.
    """
    try:
        momento = datetime.fromisoformat(f"{clave_utc}:00:00+00:00")
    except (TypeError, ValueError):
        return str(clave_utc)
    return momento.astimezone().strftime("%H:00")


def hace_cuanto(momento) -> str:
    """"hace 12 min", "hace 3 h", "recién". Para el panel de salud.

    Un "última sincronización: 21:47" obliga a hacer la cuenta mentalmente;
    "hace 12 minutos" se entiende de una.
    """
    if not momento:
        return "nunca"
    if isinstance(momento, str):
        try:
            instante = datetime.fromisoformat(momento)
            if instante.tzinfo is None:
                instante = instante.replace(tzinfo=timezone.utc)
            segundos = (datetime.now(timezone.utc) - instante).total_seconds()
        except ValueError:
            return momento
    else:
        segundos = time.time() - float(momento)

    if segundos < 0:
        return "recién"
    if segundos < 60:
        return "recién"
    if segundos < 3600:
        return f"hace {int(segundos // 60)} min"
    if segundos < 86400:
        return f"hace {int(segundos // 3600)} h"
    return f"hace {int(segundos // 86400)} días"


class ProxyRequestHandler(BaseHTTPRequestHandler):
    # Estos atributos se inyectan en la clase antes de levantar el servidor
    # (ver build_proxy_server más abajo), porque BaseHTTPRequestHandler no
    # admite un __init__ custom fácilmente junto con ThreadingHTTPServer.
    filter_engine: FilterEngine
    logger_db: LoggerDB
    notifier: TelegramNotifier
    firewall: FirewallManager
    allowlist: Allowlist
    # Base local de país/ASN. Puede no estar: en ese caso se registra igual,
    # solo que sin esos campos.
    geoip = None
    # Preferencias de lo que se MUESTRA (filtro de ruido). Nada de esto
    # participa de la decisión de bloquear.
    vista = None
    # Traductor de puerto de origen a proceso. También es contexto: si no se
    # puede averiguar, la conexión se registra igual.
    procesos = None
    # Avisos en el escritorio. Puede no estar: el proxy anda igual.
    alertas = None
    # Callable que le pide al proceso que se apague, o None si este servidor
    # no se puede apagar desde el panel (tests, o el proxy embebido en otro
    # programa). Lo inyecta run_proxy.py: ver `_handle_apagar`.
    apagar = None

    protocol_version = "HTTP/1.1"

    # Tiempo máximo de inactividad esperando datos del cliente (leer la línea
    # de pedido, headers, etc). Sin esto, un cliente que se cuelga a mitad de
    # camino (pestaña cerrada de golpe, red que se corta) deja el hilo
    # esperando para siempre. No aplica al túnel CONNECT ya establecido: ese
    # tiene su propia lógica de inactividad en _relay (ver do_CONNECT).
    timeout = 30

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Silenciamos el logging default a stderr; ya logueamos nosotros a SQLite.
        pass

    def _geo(self, ip: str | None) -> dict:
        """País, ASN y proveedor de la IP de destino, desde la base local.

        Nunca sale a la red: si la base no está descargada devuelve vacío y
        listo. Estos datos enriquecen el registro, no participan de la
        decisión de bloquear.
        """
        if not ip or self.geoip is None:
            return {"pais": "", "asn": "", "proveedor": ""}
        return self.geoip.buscar(ip)

    def _ip_de_destino(
        self, decision, host: str, socket_remoto=None, permitir_resolver: bool = True
    ) -> str:
        """La IP a la que realmente se fue esta conexión.

        No alcanza con `decision.resolved_ip`: el motor resuelve el nombre
        solo cuando lo necesita para decidir. Si el dominio estaba en la
        allowlist, o si se bloqueó antes de resolver, la decisión vuelve sin
        IP, y así el registro quedaba sin destino, sin país y sin proveedor.

        Orden de preferencia:

        1. El socket ya conectado, cuando lo hay. Es la IP exacta que se
           usó, sale gratis y no vuelve a preguntarle al DNS.
        2. La que resolvió el motor durante el filtrado.
        3. El host, si ya venía como IP literal.
        4. Una resolución de nombre, como último recurso. El sistema
           operativo la tiene cacheada del intento de conexión que se acaba
           de hacer, así que no es una consulta nueva a la red.

        Si nada de eso sale, devuelve "" y la conexión se registra igual sin
        estos datos: son contexto del registro, no parte de la decisión.

        `permitir_resolver=False` apaga el paso 4. Se usa en el camino de
        bloqueo: si el dominio se cortó por blocklist, resolverlo solo para
        adornar el registro sería mandarle una consulta DNS a un dominio que
        justamente decidimos no tocar.
        """
        if socket_remoto is not None:
            try:
                return socket_remoto.getpeername()[0]
            except OSError:
                pass
        if decision is not None and decision.resolved_ip:
            return decision.resolved_ip
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if not permitir_resolver:
            return ""
        return resolve_host_to_ip(host) or ""

    # ---------- CONNECT (HTTPS tunneling) ----------

    def do_CONNECT(self) -> None:  # noqa: N802 (nombre requerido por BaseHTTPRequestHandler)
        start = time.time()
        self._proceso()  # con el socket del cliente todavía abierto
        host, port = _partir_destino(self.path)
        if not host or port is None:
            # Antes esto era un int() pelado: un "CONNECT sitio.com:abc"
            # levantaba ValueError, mataba el hilo y el cliente se quedaba
            # sin respuesta ninguna. Y "CONNECT [::1]:443", que es lo que
            # manda cualquier navegador para un destino IPv6, rompía igual
            # porque se partía por el primer ":".
            self.send_error(400, "Destino invalido")
            return
        host = normalizar_host_de_trafico(host)

        permitido, motivo_politica = self._destino_permitido(host, port)
        if not permitido:
            decision = FilterDecision(blocked=True, reason=motivo_politica)
            self._handle_blocked(host, port, "CONNECT", decision,
                                 (time.time() - start) * 1000)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        decision = self.filter_engine.evaluate(host)
        duration_ms = (time.time() - start) * 1000

        if decision.blocked:
            self._handle_blocked(host, port, "CONNECT", decision, duration_ms)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            destino = self._ip_de_destino(decision, host)
            geo = self._geo(destino)
            self.logger_db.log_request(
                self.client_address[0], "CONNECT", host, port, "-", False,
                reason=f"error de conexión: {exc}", duration_ms=duration_ms,
                dest_ip=destino, country=geo["pais"],
                asn=geo["asn"], provider=geo["proveedor"],
                noisy=self._es_ruido(host), process=self._proceso(),
            )
            self.send_error(502, "Bad Gateway")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        # Acá el socket ya está conectado, así que la IP de destino sale del
        # propio socket: es la que realmente se usó, sin volver al DNS.
        destino = self._ip_de_destino(decision, host, socket_remoto=remote)
        geo = self._geo(destino)
        fila_id = self.logger_db.log_request(
            self.client_address[0], "CONNECT", host, port, "-", False,
            reason=decision.reason if decision.would_have_blocked else "",
            duration_ms=duration_ms,
            dest_ip=destino, country=geo["pais"],
            asn=geo["asn"], provider=geo["proveedor"],
            noisy=self._es_ruido(host), process=self._proceso(),
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

        subidos, bajados = self._relay(self.connection, remote)
        # El volumen recién se sabe cuando el túnel se cierra, que puede ser
        # media hora después de abrirlo: por eso la fila se escribió arriba y
        # se completa acá.
        self.logger_db.actualizar_volumen(fila_id, subidos, bajados)

    def _relay(self, client_sock: socket.socket, remote_sock: socket.socket) -> tuple[int, int]:
        """Reenvía bytes en ambas direcciones hasta que alguno de los dos lados
        cierre, o hasta que pasen 60s sin tráfico en ninguna dirección.

        Devuelve (subidos, bajados). Contarlos acá sale gratis, porque los
        bytes ya pasan por esta función, y es la ÚNICA forma que tiene el
        proxy de medir volumen en HTTPS: el contenido va cifrado, pero
        cuánto se movió y para qué lado se ve igual. Es lo que permite notar
        una exfiltración: un destino al que le subiste 800 MB se distingue de
        una visita normal aunque no se pueda leer nada de lo que viajó.
        """
        sockets = [client_sock, remote_sock]
        subidos = 0
        bajados = 0
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
                    if sock is client_sock:
                        subidos += len(data)
                    else:
                        bajados += len(data)
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
        return subidos, bajados

    # ---------- HTTP normal (GET/POST/etc.) ----------

    def _handle_http_method(self, method: str) -> None:
        start = time.time()
        self._proceso()  # con el socket del cliente todavía abierto
        parsed = urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]
        host = normalizar_host_de_trafico(host)
        try:
            port = parsed.port or 80
        except ValueError:
            self.send_error(400, "Puerto invalido")
            return

        permitido, motivo_politica = self._destino_permitido(host, port)
        if not permitido:
            decision = FilterDecision(blocked=True, reason=motivo_politica)
            self._handle_blocked(host, port, method, decision,
                                 (time.time() - start) * 1000)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        decision = self.filter_engine.evaluate(host)
        duration_ms = (time.time() - start) * 1000

        if decision.blocked:
            self._handle_blocked(host, port, method, decision, duration_ms)
            self.send_error(403, "Forbidden by SecureProxy")
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            # Antes esto era un int() pelado: un "Content-Length: abc"
            # mataba el hilo con un ValueError y el cliente no recibía nada.
            self.send_error(400, "Content-Length invalido")
            return
        if content_length < 0 or content_length > MAX_BODY:
            # Sin tope, un "Content-Length: 3000000000" hacía que rfile.read()
            # reservara 3 GB de una. En Windows, que no hace overcommit, eso
            # es memoria comprometida de verdad: unos pocos pedidos dejan la
            # máquina sin nada. Y un valor negativo hacía read(-1), que se
            # queda leyendo hasta que el cliente cierre.
            self.send_error(413, "Cuerpo demasiado grande")
            return
        body = self.rfile.read(content_length) if content_length else None
        subidos = content_length

        forward_headers = _headers_para_reenviar(self.headers)

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
            destino = self._ip_de_destino(decision, host)
            geo = self._geo(destino)
            self.logger_db.log_request(
                self.client_address[0], method, host, port, parsed.path, False,
                reason=f"error reenviando pedido: {exc}", duration_ms=duration_ms,
                dest_ip=destino, country=geo["pais"],
                asn=geo["asn"], provider=geo["proveedor"],
                noisy=self._es_ruido(host), process=self._proceso(),
            )
            self.send_error(502, "Bad Gateway")
            return

        # La IP de destino se saca del socket que abrió `requests`, antes de
        # consumir el cuerpo: apenas se lee `response.content`, urllib3
        # devuelve la conexión al pool y ya no se puede preguntar. Si el
        # atributo interno no está (cambia entre versiones), se cae al
        # camino de siempre en _ip_de_destino.
        socket_saliente = None
        try:
            socket_saliente = response.raw._connection.sock
        except AttributeError:
            pass
        destino = self._ip_de_destino(decision, host, socket_remoto=socket_saliente)
        geo = self._geo(destino)

        # La respuesta se copia POR PEDAZOS, no entera en memoria. Antes se
        # hacía `body = response.content`, y medido con una descarga de 400
        # MB por HTTP plano el proceso pasaba de 39 MB a 593 MB de RSS: una
        # vez y media el tamaño del archivo, por conexión y sin techo. Y el
        # cliente no recibía un solo byte hasta que terminaba de bajar todo.
        # No hace falta que sea malicioso: alcanza con bajar un instalador.
        largo_declarado = response.headers.get("Content-Length")
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(key, value)
        if largo_declarado is not None:
            # Con largo conocido se puede mantener keep-alive.
            self.send_header("Content-Length", largo_declarado)
        else:
            # Sin largo (respuesta chunked del origen) el cliente necesita
            # otra forma de saber dónde termina: se cierra al final.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()

        bajados = 0
        try:
            for pedazo in response.iter_content(chunk_size=BUFFER_SIZE):
                if not pedazo:
                    continue
                bajados += len(pedazo)
                self.wfile.write(pedazo)
        except (requests.RequestException, OSError):
            # El cliente cortó, o el origen se cayó a mitad de la bajada. La
            # respuesta ya empezó a salir, así que no se puede mandar un
            # error: se corta y se registra lo que se alcanzó a mover.
            self.close_connection = True
        finally:
            response.close()

        self.logger_db.log_request(
            self.client_address[0], method, host, port, parsed.path, False,
            reason=decision.reason if decision.would_have_blocked else "",
            duration_ms=duration_ms,
            dest_ip=destino, country=geo["pais"],
            asn=geo["asn"], provider=geo["proveedor"],
            noisy=self._es_ruido(host), process=self._proceso(),
            bytes_out=subidos, bytes_in=bajados,
        )

    def _es_para_nosotros(self, parsed) -> bool:
        """¿Este pedido es PARA el proxy, o es tráfico para reenviar?

        En el puerto que proxea llegan pedidos de dos formas:

        - **relativa** (`GET /dashboard`): así habla un navegador que entró
          derecho. No hay destino declarado: es para nosotros.
        - **absoluta** (`GET http://sitio.com/dashboard`): así habla un
          navegador que tiene este proxy configurado. Acá el destino importa:
          si apunta a nuestra propia dirección es el panel; si apunta a
          cualquier otro lado, es tráfico a proxear.

        Sin esta distinción alcanzaba con que un sitio cualquiera tuviera un
        path igual al de una ruta del panel para que el proxy la ejecutara en
        vez de reenviar el pedido. En el peor caso eso significaba que
        cualquier página podía cambiar la configuración de SecureProxy con
        solo hacerte visitar algo como `http://loquesea.com/config?k=...`, o
        que `http://loquesea.com/dashboard` devolviera nuestro panel en lugar
        del sitio.
        """
        if not parsed.netloc:
            return True  # forma relativa: entraron directo al panel
        if (parsed.port or 80) != self.server.server_address[1]:
            return False
        # Cualquier nombre que apunte a esta misma máquina cuenta: el
        # navegador puede pedir 127.0.0.1, localhost o ::1 indistintamente.
        return (parsed.hostname or "") in ("127.0.0.1", "localhost", "::1")

    def _serve_health(self) -> None:
        """Chequeo liviano, para el panel .bat y para SecureCenter."""
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    # Rutas que CAMBIAN algo. Se separan de las de lectura porque necesitan
    # protección contra CSRF: son las que un sitio web podría disparar sin
    # que te enteres.
    RUTAS_QUE_CAMBIAN = frozenset({
        "/allow", "/unallow", "/blockdomain", "/unblockdomain",
        "/clear-cache", "/config", "/sincronizar", "/nivel",
        "/ocultar", "/mostrar", "/apagar",
    })

    # Nombres por los que es legítimo llegar al panel. Todo lo demás se
    # rechaza: ver `_host_permitido`.
    HOSTS_PERMITIDOS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

    def _host_permitido(self) -> bool:
        """¿El pedido llegó pidiendo por un nombre que es realmente nuestro?

        Sin esto el panel es vulnerable a DNS rebinding: un atacante publica
        `attacker.com` con TTL 0, te hace entrar, y después reapunta ese
        nombre a 127.0.0.1. A partir de ahí su JavaScript queda del MISMO
        origen que el panel para el navegador, así que puede LEER las
        respuestas: todo tu historial de navegación, con procesos y todo.

        La defensa es barata y definitiva: el navegador manda en `Host` el
        nombre que el usuario escribió. Si no es uno de los nuestros, no es
        un pedido nuestro.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            # Sin header Host no puede ser un navegador: HTTP/1.1 lo exige y
            # todos lo mandan. Y sin navegador no hay DNS rebinding, que es
            # justo lo que este chequeo previene. Así que un cliente simple
            # (un socket crudo, curl -0, SecureCenter) pasa.
            return True
        sin_puerto = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return sin_puerto in self.HOSTS_PERMITIDOS or host in self.HOSTS_PERMITIDOS

    def _origen_confiable(self) -> bool:
        """¿Esta acción la pidió el panel, o la disparó otro sitio?

        El agujero que cierra: todas las acciones del panel son GET sin
        token, así que cualquier página que visites puede hacer
        `<img src="http://127.0.0.1:8889/config?k=mode&v=audit">` y dejar el
        proxy en modo audit, o sea sin bloquear nada. No hace falta que lea
        la respuesta para que el daño esté hecho, así que la política de
        mismo origen del navegador no protege de esto. Peor todavía:
        `/allow?domain=su-c2.com` le pone su propio dominio en la lista
        blanca, y `/ocultar?domain=su-c2.com` esconde del panel el tráfico
        hacia él.

        Se chequea en dos capas, porque ninguna sola alcanza:

        1. `Sec-Fetch-Site`, que mandan los navegadores actuales y que el
           JavaScript de una página NO puede falsificar. `same-origin` es el
           panel hablando consigo mismo; `none` es alguien escribiendo la
           URL en la barra. Cualquier otro valor es otro sitio.
        2. `Origin`/`Referer` para los navegadores que no mandan el primero.

        Si no viene ninguno de los tres, se acepta: es el caso de `curl`, del
        panel `.bat` y de los tests, que no son un navegador y por lo tanto
        no son el vector de este ataque.
        """
        sitio = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sitio:
            return sitio in ("same-origin", "none")

        for cabecera in ("Origin", "Referer"):
            valor = (self.headers.get(cabecera) or "").strip()
            if not valor:
                continue
            partes = urlsplit(valor)
            nombre = (partes.hostname or "").lower()
            return nombre in self.HOSTS_PERMITIDOS or nombre in ("127.0.0.1", "localhost", "::1")
        return True

    def _accion_autorizada(self, clean_path: str) -> bool:
        """Deja pasar la acción solo si el pedido es nuestro y viene de acá."""
        if not self._host_permitido():
            return False
        if clean_path in self.RUTAS_QUE_CAMBIAN and not self._origen_confiable():
            return False
        return True

    def _rechazar_por_origen(self) -> None:
        cuerpo = (
            "SecureProxy: pedido rechazado.\n\n"
            "El panel solo acepta pedidos hechos desde el propio panel, "
            "abierto en 127.0.0.1. Esto existe para que ninguna pagina web "
            "pueda cambiarte la configuracion del proxy sin que te enteres.\n"
        ).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        # El dashboard vive en su propio puerto (ver DashboardOnlyRequestHandler
        # más abajo), pero estas rutas siguen respondiendo también acá por
        # compatibilidad con links viejos, y SOLO cuando el pedido apunta a
        # esta misma máquina: ver _es_para_nosotros.
        parsed_path = urlsplit(self.path)
        clean_path = parsed_path.path.rstrip("/")
        dashboard_routes = {
            "/dashboard": self._serve_dashboard,
            "/allow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=True),
            "/unallow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=False),
            "/blockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=True),
            "/unblockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=False),
            "/clear-cache": self._handle_clear_cache,
            "/config": lambda: self._handle_config_change(parsed_path.query),
            "/osint": self._serve_dashboard,
            "/export.csv": lambda: self._exportar(parsed_path.query, "csv"),
            "/export.json": lambda: self._exportar(parsed_path.query, "json"),
            "/sincronizar": self._sincronizar_feeds,
            "/nivel": lambda: self._aplicar_nivel(
                (parse_qs(parsed_path.query).get("v") or [""])[0]
            ),
            "/ocultar": lambda: self._handle_ruido(parsed_path.query, add=True),
            "/mostrar": lambda: self._handle_ruido(parsed_path.query, add=False),
        }
        if clean_path in dashboard_routes and self._es_para_nosotros(parsed_path):
            if not self._accion_autorizada(clean_path):
                self._rechazar_por_origen()
                return
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

    def _redirect_to_dashboard(self, aviso: str = "") -> None:
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
        destino = "/dashboard"
        if aviso:
            # El aviso viaja en la URL y lo muestra la página siguiente. Es
            # importante que se vea: una lista que calladamente guarda algo
            # distinto de lo que escribiste es una fuente de sorpresas.
            destino += "?aviso=" + quote(aviso)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _handle_list_edit(self, target_list, query_string: str, add: bool) -> None:
        """Endpoint común para agregar/quitar un dominio de una lista
        (allowlist o blocklist manual). Pensado para uso local únicamente
        (no valida quién llama, ya que el dashboard solo escucha en loopback).

        Al agregar, primero NORMALIZA lo que se escribió y después valida.
        Ese orden importa: nadie copia dominios, uno copia la barra del
        navegador, así que lo que llega acá suele ser
        "https://www.ejemplo.com/algo". Antes eso se rechazaba en silencio y
        había que editarlo a mano; ahora se limpia solo y se avisa qué se le
        sacó. Al quitar no hace falta nada de esto: si no matchea, no pasa
        nada."""
        params = parse_qs(query_string)
        crudo = (params.get("domain") or [""])[0].strip()
        if not crudo:
            self._redirect_to_dashboard()
            return

        if not add:
            target_list.remove_and_reload(crudo)
            self._redirect_to_dashboard()
            return

        domain, avisos = normalizar_dominio(crudo)
        if not is_valid_domain(domain):
            self._redirect_to_dashboard(
                f"No pude entender \"{crudo}\" como un dominio. Ejemplos que sí "
                "funcionan: ejemplo.com, https://www.ejemplo.com/algo, 8.8.8.8"
            )
            return

        target_list.add_and_reload(domain)
        if avisos:
            self._redirect_to_dashboard(
                f"Se guardó como \"{domain}\": " + "; ".join(avisos) + "."
            )
        else:
            self._redirect_to_dashboard()

    def _handle_ruido(self, query_string: str, add: bool) -> None:
        """Agrega o saca un dominio de la lista de ruido del panel.

        Lo que viene de fábrica cubre el ruido de SISTEMA: Windows, los
        certificados, el reloj, las comprobaciones de internet. Pero el ruido
        de cada máquina es distinto: si tenés Docker Desktop abierto todo el
        día, `desktop.docker.com` te va a comer el primer puesto del Top 10 y
        eso no va a estar nunca en una lista genérica. Poder sacarlo de un
        clic es la diferencia entre que la funcionalidad sirva o no.

        Después de tocar la lista se remarca el historial, así el cambio se
        ve en el refresco siguiente y no dentro de un rato.
        """
        vista = getattr(self, "vista", None)
        if vista is None:
            self._redirect_to_dashboard()
            return

        crudo = (parse_qs(query_string).get("domain") or [""])[0].strip()
        dominio, _avisos = normalizar_dominio(crudo)
        if not is_valid_domain(dominio):
            self._redirect_to_dashboard()
            return

        if add:
            vista.agregar(dominio)
            aviso = (
                f"\"{dominio}\" ya no se muestra en el panel. Se sigue registrando "
                "y se sigue filtrando igual que antes: solo dejó de aparecer en el "
                "historial y en las estadísticas. Para revertirlo, buscalo en "
                "Configuración."
            )
        else:
            vista.quitar(dominio)
            aviso = f"\"{dominio}\" vuelve a mostrarse en el panel."

        self.logger_db.remarcar_ruido(vista.es_ruidoso)
        self._redirect_to_dashboard(aviso)

    def _handle_clear_cache(self) -> None:
        """Endpoint del botón "Borrar cache": vacía el cache (en memoria y
        persistente) de resultados de AbuseIPDB."""
        self.filter_engine.abuseipdb_client.clear_cache()
        self._redirect_to_dashboard()

    def _handle_apagar(self) -> None:
        """Endpoint del botón "Apagar proxy": corta el proceso entero.

        Por qué no se manda una señal: `os.kill(os.getpid(), SIGINT)` funciona
        en Linux pero en Windows no hay forma limpia de mandarle SIGINT a un
        proceso puntual (CTRL_C_EVENT va al grupo de consola entero y se lleva
        puesta también la terminal de al lado). Así que se usa el mismo
        mecanismo en los dos: `apagar` es un callable que le avisa al hilo
        principal, y ese hilo hace exactamente el mismo cierre ordenado que
        con Ctrl+C, incluido el borrado de `data/proxy.pid`.

        El pedido se atiende en dos tiempos a propósito: primero se contesta
        la página y recién después se dispara el apagado. Si se hiciera al
        revés, el proceso podría morir antes de que la respuesta llegue y el
        navegador mostraría un error de conexión justo cuando la acción
        funcionó bien.

        Ojo con quién puede llamar acá: `/apagar` está en RUTAS_QUE_CAMBIAN,
        así que pasa por el chequeo anti-CSRF. Sin eso, cualquier página que
        visitaras podía apagarte el proxy con un `<img src=...>` y dejarte sin
        filtrado sin que te enteres, que es peor que cambiar una opción.
        """
        if not callable(type(self).apagar):
            self._redirect_to_dashboard(
                "Este proxy no se puede apagar desde el panel: no fue arrancado "
                "con scripts/run_proxy.py."
            )
            return

        cuerpo = PAGINA_DE_APAGADO.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        try:
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

        pedir_apagado = type(self).apagar

        def _apagar_en_un_momento() -> None:
            # Medio segundo para que la respuesta termine de salir por el
            # socket y el navegador la pinte antes de que el proceso cierre.
            time.sleep(0.5)
            pedir_apagado()

        threading.Thread(target=_apagar_en_un_momento, daemon=True).start()

    @staticmethod
    def _render_editable_list(
        items: list[str], remove_endpoint: str, vacio: str = "",
    ) -> str:
        if not items:
            return f"<p class='empty'>{vacio or 'No hay dominios cargados todavía.'}</p>"
        rows = "".join(
            f"<tr><td title='{html_lib.escape(domain)}'>"
            f"{html_lib.escape(limpiar_para_mostrar(domain))}</td>"
            f"<td><a class='danger' href=\"{remove_endpoint}?domain={quote(domain)}\" "
            f"data-dominio='{html_lib.escape(domain)}' "
            f"onclick=\"return confirmarAccion(this, 'quitar')\">Quitar</a></td></tr>"
            for domain in items
        )
        return f"<table><tr><th>Dominio</th><th>Acción</th></tr>{rows}</table>"

    # ---------- configuración editable desde el dashboard ----------

    # Solo estas opciones se pueden tocar desde la web, y cada una declara
    # cómo se valida. Es una lista blanca explícita: nada de escribir claves
    # arbitrarias en el config.yaml desde una URL.
    OPCIONES_EDITABLES = {
        "mode": {
            "seccion": "filtering",
            "valores": ("enforce", "audit"),
            "tipo": "opcion",
        },
        "abuseipdb_min_score": {
            "seccion": "filtering",
            "min": 0,
            "max": 100,
            "tipo": "numero",
        },
        "check_tor_exit_nodes": {"seccion": "filtering", "tipo": "booleano"},
        "block_unknown_domains": {"seccion": "filtering", "tipo": "booleano"},
        "firewall_enabled": {
            "seccion": "firewall",
            "clave_real": "enabled",
            "tipo": "booleano",
        },
        # Esta no toca el motor: cambia lo que MUESTRA el panel. Vive en su
        # propia sección del YAML justamente para que quede clara la
        # diferencia entre filtrar tráfico y filtrar la vista.
        "hide_noise": {"seccion": "dashboard", "tipo": "booleano"},
        "alerts_enabled": {
            "seccion": "alerts",
            "clave_real": "enabled",
            "tipo": "booleano",
        },
    }

    # Niveles de seguridad: atajos que fijan varias opciones de golpe.
    #
    # No son un mecanismo nuevo: cada nivel escribe las MISMAS opciones que se
    # pueden tocar una por una más abajo. Es un atajo, no una capa aparte, y
    # por eso después de aplicar uno se sigue viendo -y se puede cambiar- cada
    # valor por separado.
    NIVELES = {
        "normal": {
            "titulo": "Normal",
            "subtitulo": "recomendado para todos los días",
            "descripcion": (
                "Bloquea de verdad, con el umbral de reputación equilibrado. "
                "Es el que deberías tener puesto salvo que estés investigando algo."
            ),
            "opciones": {
                "mode": "enforce",
                "abuseipdb_min_score": 50,
                "check_tor_exit_nodes": True,
                "block_unknown_domains": False,
            },
        },
        "estricto": {
            "titulo": "Estricto",
            "subtitulo": "más cerrado, algún falso positivo",
            "descripcion": (
                "Baja el umbral de reputación a 25, así una IP con antecedentes "
                "moderados ya se bloquea. Vas a ver algún sitio legítimo cortado; "
                "para esos está la lista blanca."
            ),
            "opciones": {
                "mode": "enforce",
                "abuseipdb_min_score": 25,
                "check_tor_exit_nodes": True,
                "block_unknown_domains": False,
            },
        },
        "paranoico": {
            "titulo": "Paranoico",
            "subtitulo": "diagnóstico - NO bloquea",
            "descripcion": (
                "Umbral 10 y, además, trata como sospechoso todo dominio que no "
                "esté en la lista blanca. Va en modo audit a propósito: aplicado "
                "de verdad te dejaría sin internet en el primer minuto. Sirve para "
                "VER qué pasaría con una política de lista blanca y armarla mirando "
                "el historial, no para dejarlo puesto."
            ),
            "opciones": {
                "mode": "audit",
                "abuseipdb_min_score": 10,
                "check_tor_exit_nodes": True,
                "block_unknown_domains": True,
            },
        },
    }

    def _aplicar_nivel(self, nivel: str) -> None:
        """Escribe todas las opciones del nivel y las aplica en caliente."""
        from .config_loader import PROJECT_ROOT
        from .config_writer import set_value

        spec = self.NIVELES.get(nivel)
        if spec is None:
            return self._redirect_to_dashboard()

        yaml_path = PROJECT_ROOT / "config" / "config.yaml"
        for clave, valor in spec["opciones"].items():
            set_value(yaml_path, "filtering", clave, valor)
        set_value(yaml_path, "filtering", "security_level", nivel)

        engine = self.filter_engine
        engine.mode = spec["opciones"]["mode"]
        engine.abuseipdb_min_score = spec["opciones"]["abuseipdb_min_score"]
        engine.check_tor_exit_nodes = spec["opciones"]["check_tor_exit_nodes"]
        engine.block_unknown_domains = spec["opciones"]["block_unknown_domains"]

        self.logger_db.log_request(
            "127.0.0.1", "CONFIG", "nivel-de-seguridad", 0, nivel, False,
            reason=f"nivel de seguridad cambiado a {nivel}",
        )
        self._redirect_to_dashboard()

    def _nivel_actual(self) -> str:
        """Qué nivel refleja la configuración que hay puesta ahora mismo.

        Se deduce de los valores reales en vez de confiar en lo guardado: si
        alguien cambió una opción suelta después de aplicar un nivel, lo
        honesto es decir "personalizado" y no seguir mostrando el nivel viejo.
        """
        engine = self.filter_engine
        actual = {
            "mode": getattr(engine, "mode", "enforce"),
            "abuseipdb_min_score": getattr(engine, "abuseipdb_min_score", 50),
            "check_tor_exit_nodes": bool(getattr(engine, "check_tor_exit_nodes", True)),
            "block_unknown_domains": bool(getattr(engine, "block_unknown_domains", False)),
        }
        for nombre, spec in self.NIVELES.items():
            if spec["opciones"] == actual:
                return nombre
        return "personalizado"

    def _handle_config_change(self, query_string: str) -> None:
        from .config_loader import PROJECT_ROOT
        from .config_writer import set_value

        params = parse_qs(query_string)
        clave = (params.get("k") or [""])[0]
        valor_crudo = (params.get("v") or [""])[0]
        spec = self.OPCIONES_EDITABLES.get(clave)
        if spec is None:
            self._redirect_to_dashboard()
            return

        # Validación por tipo, antes de tocar nada.
        if spec["tipo"] == "opcion":
            if valor_crudo not in spec["valores"]:
                self._redirect_to_dashboard()
                return
            valor = valor_crudo
        elif spec["tipo"] == "booleano":
            valor = valor_crudo.lower() in ("1", "true", "on", "si", "sí")
        else:  # numero
            try:
                valor = int(valor_crudo)
            except ValueError:
                self._redirect_to_dashboard()
                return
            if not (spec["min"] <= valor <= spec["max"]):
                self._redirect_to_dashboard()
                return

        clave_real = spec.get("clave_real", clave)
        # 1) Se persiste en el archivo, para que sobreviva al reinicio.
        set_value(PROJECT_ROOT / "config" / "config.yaml", spec["seccion"], clave_real, valor)
        # 2) Y se aplica EN CALIENTE al objeto que ya está corriendo: estas
        #    tres opciones se leen en cada request, así que el cambio tiene
        #    efecto en la próxima conexión, sin reiniciar nada.
        if clave == "mode":
            self.filter_engine.mode = valor
        elif clave == "abuseipdb_min_score":
            self.filter_engine.abuseipdb_min_score = valor
        elif clave == "check_tor_exit_nodes":
            self.filter_engine.check_tor_exit_nodes = valor
        elif clave == "block_unknown_domains":
            self.filter_engine.block_unknown_domains = valor
        elif clave == "firewall_enabled":
            self.firewall.enabled = valor
        elif clave == "hide_noise":
            vista = getattr(self, "vista", None)
            if vista is not None:
                vista.ocultar_ruido = valor
        elif clave == "alerts_enabled":
            alertas = getattr(self, "alertas", None)
            if alertas is not None:
                alertas.enabled = valor

        self._redirect_to_dashboard()

    def _render_niveles(self) -> str:
        actual = self._nivel_actual()
        tarjetas = []
        for nombre, spec in self.NIVELES.items():
            activo = actual == nombre
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = "<span class='badge-activo'>&#10003; en uso</span>"
            else:
                opciones = spec["opciones"]
                resumen = (
                    f"modo {opciones['mode']}, umbral {opciones['abuseipdb_min_score']}"
                )
                accion = (
                    f"<form method='get' action='/nivel' "
                    f"onsubmit=\"return confirm('¿Pasar al nivel {spec['titulo']}? "
                    f"Queda: {resumen}.')\">"
                    f"<input type='hidden' name='v' value='{nombre}'>"
                    f"<button type='submit'>Usar {spec['titulo']}</button></form>"
                )
            tarjetas.append(
                f"<div class='{clase}'><div class='optcard-head'>"
                f"<span class='optcard-title'>{spec['titulo']}</span>"
                f"<span class='optcard-sub'>{spec['subtitulo']}</span></div>"
                f"<p class='hint'>{spec['descripcion']}</p>{accion}</div>"
            )
        aviso = (
            "<p class='hint'>Ahora mismo la configuración no coincide con "
            "ningún nivel: cambiaste alguna opción suelta después de aplicar "
            "uno. No es un problema, es solo para que sepas por qué no hay "
            "ninguno marcado.</p>"
            if actual == "personalizado" else ""
        )
        return (
            "<h2>Nivel de seguridad</h2>"
            "<p class='hint'>Un atajo que fija varias opciones de golpe. No es "
            "un mecanismo aparte: escribe las mismas opciones que podés tocar "
            "una por una más abajo, así que después seguís viendo y pudiendo "
            "cambiar cada valor.</p>"
            + aviso
            + f"<div class='opciones'>{''.join(tarjetas)}</div>"
        )

    def _render_config_panel(self) -> str:
        """Pestaña de configuración: lo que antes solo se podía cambiar
        editando el config.yaml a mano."""
        engine = self.filter_engine
        modo = getattr(engine, "mode", "enforce")
        score = getattr(engine, "abuseipdb_min_score", 50)
        tor = bool(getattr(engine, "check_tor_exit_nodes", True))
        fw = bool(getattr(self.firewall, "enabled", False))
        desconocidos = bool(getattr(engine, "block_unknown_domains", False))
        vista = getattr(self, "vista", None)
        ruido = bool(vista.ocultar_ruido) if vista is not None else False
        cuantos_ruidosos = vista.cantidad_de_dominios if vista is not None else 0
        alertas_obj = getattr(self, "alertas", None)
        avisos = bool(alertas_obj.enabled) if alertas_obj is not None else False
        ruido_lista_html = self._render_editable_list(
            vista.dominios_manuales() if vista is not None else [], "/mostrar",
            vacio="No agregaste ninguno todavía.",
        )

        def tarjeta_modo(valor: str, etiqueta: str, subtitulo: str,
                         descripcion: str, confirmacion: str) -> str:
            """Cada modo es una tarjeta seleccionable, no un botón suelto: se
            ve cuál está activo de un vistazo y la descripción queda debajo,
            no apretada al costado."""
            activo = modo == valor
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = (
                    "<span class='badge-activo'>&#10003; en uso</span>"
                )
            else:
                accion = (
                    f"<form method='get' action='/config' "
                    f"onsubmit=\"return confirm('{confirmacion}')\">"
                    f"<input type='hidden' name='k' value='mode'>"
                    f"<input type='hidden' name='v' value='{valor}'>"
                    f"<button type='submit'>Cambiar a este modo</button></form>"
                )
            return (
                f"<div class='{clase}'>"
                f"<div class='optcard-head'><span class='optcard-title'>{etiqueta}</span>"
                f"<span class='optcard-sub'>{subtitulo}</span></div>"
                f"<p class='hint'>{descripcion}</p>{accion}</div>"
            )

        def interruptor(clave: str, encendido: bool, etiqueta_on: str,
                        etiqueta_off: str, confirmacion: str = "") -> str:
            nuevo = "0" if encendido else "1"
            texto = etiqueta_off if encendido else etiqueta_on
            clase = "danger-btn" if encendido else "ok-btn"
            pill = "pill on" if encendido else "pill off"
            estado = "activado" if encendido else "desactivado"
            confirm = f" onsubmit=\"return confirm('{confirmacion}')\"" if confirmacion else ""
            # El botón va primero (pegado al margen izquierdo) y la leyenda
            # de estado a su derecha: se lee "qué puedo hacer" y después
            # "cómo está ahora", que es el orden natural al operar.
            return (
                f"<div class='fila-switch'>"
                f"<form method='get' action='/config'{confirm}>"
                f"<input type='hidden' name='k' value='{clave}'>"
                f"<input type='hidden' name='v' value='{nuevo}'>"
                f"<button class='{clase}' type='submit'>{texto}</button></form>"
                f"<span class='leyenda'>actualmente <span class='{pill}'>{estado}</span></span>"
                f"</div>"
            )

        aviso_audit = (
            "En modo AUDIT el proxy DEJA PASAR TODO: no vas a estar protegido, "
            "solo se registra qué se habría bloqueado. Es para diagnosticar un "
            "rato, no para dejarlo puesto. ¿Cambiar a Audit?"
        )
        aviso_enforce = "¿Volver a Enforce? El proxy vuelve a bloquear de verdad."
        salto = chr(92) + "n"  # \n literal para el confirm() del navegador
        aviso_tor = (
            "¿Desactivar la detección de nodos TOR? Las conexiones a nodos de "
            "salida de TOR dejarán de bloquearse."
            if tor else "¿Activar la detección de nodos de salida TOR?"
        )
        aviso_desconocidos = (
            "Esto bloquea TODO dominio que no esté en tu lista blanca. En modo "
            "enforce te deja sin internet al instante. ¿Seguro?"
        )
        aviso_fw = (
            "¿Desactivar el bloqueo por firewall? (las reglas ya escritas siguen puestas)"
            if fw else
            "OJO: esto escribe reglas REALES en el firewall de Windows contra las "
            "IPs bloqueadas, y quedan puestas aunque apagues el proxy."
            + salto + salto + "¿Activarlo igual?"
        )

        aviso_avisos = (
            "¿Desactivar los avisos en el escritorio? Vas a tener que abrir el "
            "panel para enterarte de los bloqueos."
            if avisos else
            "¿Activar los avisos en el escritorio? Vas a recibir una notificación "
            "de Windows cuando se bloquee algo grave."
        )

        aviso_ruido = (
            "¿Volver a mostrar la telemetría y las comprobaciones en el panel? "
            "Las estadísticas se van a llenar de dominios de fondo."
            if ruido else
            "¿Ocultar del panel la telemetría, las comprobaciones de internet y "
            "las actualizaciones? No cambia qué se bloquea: solo deja de "
            "mostrarlas en el historial y en las estadísticas."
        )

        return f"""
    {self._render_niveles()}

    <h2>Modo de filtrado</h2>
    <p class="hint">Se aplica al instante, sin reiniciar. Son los dos únicos
    modos posibles: <strong>Enforce es el normal</strong> y el que conviene
    tener siempre; Audit es temporal, para diagnosticar.</p>
    <div class="opciones">
      {tarjeta_modo("enforce", "Enforce", "normal · recomendado",
                    "Bloquea de verdad las conexiones que matchean una regla. Es el modo por defecto y el que deberías tener siempre puesto.",
                    aviso_enforce)}
      {tarjeta_modo("audit", "Audit", "diagnóstico · temporal",
                    "Evalúa todas las reglas igual, pero deja pasar el tráfico y solo registra qué habría bloqueado. Sirve para probar una lista o un umbral nuevo sin cortar nada. Mientras esté activo NO estás protegido.",
                    aviso_audit)}
    </div>

    <h2>Sensibilidad de reputación de IP (AbuseIPDB)</h2>
    <p class="hint">Score de 0 a 100 a partir del cual se bloquea la IP de destino.
    Más bajo = más estricto y más falsos positivos. Se aplica al instante.</p>
    <form class="add-form" method="get" action="/config">
      <input type="hidden" name="k" value="abuseipdb_min_score">
      <input type="number" name="v" min="0" max="100" value="{score}" required>
      <button class="ok-btn" type="submit">Guardar</button>
    </form>
    <p class="hint">Actual: <strong>{score}</strong> &nbsp;·&nbsp; 25 = estricto · 50 = equilibrado (default) · 75 = permisivo</p>

    <h2>Detección de nodos de salida TOR</h2>
    <p class="hint">Bloquea conexiones cuya IP de destino es un nodo de salida
    conocido de TOR. Se aplica al instante.</p>
    {interruptor("check_tor_exit_nodes", tor, "Activar", "Desactivar", aviso_tor)}

    <h2>Bloquear dominios desconocidos (lista blanca estricta)</h2>
    <p class="hint">Trata como sospechoso todo dominio que no esté en la lista
    blanca. Aplicado de verdad te deja sin internet en el primer minuto, así
    que tiene sentido solo junto al modo audit: te muestra qué habría que
    permitir, para armar la lista mirando el historial.</p>
    {interruptor("block_unknown_domains", desconocidos, "Activar (solo con audit)", "Desactivar", aviso_desconocidos)}

    <h2>Ocultar telemetría y comprobaciones del panel</h2>
    <p class="hint">El proxy ve TODO lo que hace la PC, y buena parte es ruido
    previsible: el navegador preguntando si hay internet, Windows chequeando
    actualizaciones, cada conexión TLS validando un certificado. Con eso, el
    Top 10 de destinos son diez dominios de comprobación y no se ve si apareció
    algo raro. Esto los saca de la <strong>vista</strong> (historial y
    estadísticas). <strong>No cambia nada de lo que se bloquea</strong>: las
    conexiones se siguen registrando, el panel te dice cuántas está ocultando,
    y buscar un dominio ignora el filtro a propósito. La lista está en
    <code>data/noisy_domains.txt</code> ({cuantos_ruidosos} dominios) y se
    puede editar a mano.</p>
    {interruptor("hide_noise", ruido, "Activar", "Desactivar", aviso_ruido)}

    <h3>Dominios que se están ocultando</h3>
    <p class="hint">La lista que viene de fábrica cubre el ruido de sistema
    (Windows, certificados, reloj, comprobaciones de internet). El ruido de tus
    aplicaciones -Docker, Steam, lo que tengas abierto todo el día- lo sumás
    acá, o de un clic desde <strong>Consultar</strong>. También podés sacar
    cualquiera de los que vienen puestos.</p>
    <form class="add-form" method="get" action="/ocultar">
      <input type="text" name="domain" placeholder="desktop.docker.com" required>
      <button type="submit">Ocultar del panel</button>
    </form>
    <details class="plegable">
      <summary>Ver los {cuantos_ruidosos} dominios ocultos</summary>
      {ruido_lista_html}
    </details>

    <h2>Avisos en el escritorio</h2>
    <p class="hint">Una notificación de Windows cuando se bloquea algo que
    significa algo: una IP de comando-y-control, un pool de minería, una IP con
    mala reputación. Un dominio de tu lista manual no dispara nada, porque de
    eso ya sabés. Hay un aviso por dominio cada 10 minutos y un techo de 12 por
    hora: una herramienta que te tapa la pantalla termina apagada, y apagada no
    avisa nada.</p>
    {interruptor("alerts_enabled", avisos, "Activar", "Desactivar", aviso_avisos)}

    <h2>Bloqueo por firewall real</h2>
    <p class="hint">Además de cortar la conexión, escribe reglas REALES en el
    firewall del sistema contra esa IP. Es potente pero invasivo: las reglas
    quedan puestas aunque apagues el proxy. Dejalo desactivado salvo que sepas
    lo que hacés.</p>
    {interruptor("firewall_enabled", fw, "Activar (con cuidado)", "Desactivar", aviso_fw)}

    <h2>Lo que se cambia desde el archivo</h2>
    <p class="hint">Estas opciones necesitan reiniciar el proxy, así que viven
    solo en <code>config/config.yaml</code>: los puertos (proxy y dashboard),
    cada cuánto se refrescan los feeds de amenazas, el tamaño del pool de
    threads, y las notificaciones por Telegram (que además necesitan cargar el
    token en el archivo <code>.env</code>).</p>
"""

    # ---------- fragmentos que se refrescan solos (SSE) ----------

    # Tope de pestañas con la conexión de eventos abierta a la vez. Cada una
    # ocupa un hilo del pool mientras esté abierta, así que conviene un techo:
    # el navegador que quede afuera vuelve solo al refresco clásico.
    MAX_CLIENTES_SSE = 8
    _sse_lock = threading.Lock()
    _sse_clientes = 0

    def _fragmentos(self, consulta: str) -> dict:
        """Las partes del panel que cambian solas, cada una entera y lista
        para reemplazar en su lugar.

        Se arman todas juntas y de la misma lectura, para que las tarjetas y
        la tabla no queden contando cosas de momentos distintos.
        """
        ocultos = self._ocultar_ruido()
        stats = self.logger_db.stats(ocultar=ocultos)
        total = stats["total_requests"]
        blocked = stats["blocked_requests"]
        ocultas = stats.get("ocultas", 0)
        tasa = (blocked / total * 100) if total else 0.0
        cache = self.filter_engine.abuseipdb_client.persistent_cache
        en_cache = cache.count() if cache is not None else 0

        filas = self.logger_db.buscar(
            texto=consulta, solo_bloqueadas=True, limit=50, ocultar=ocultos
        )

        tarjetas = (
            f'<div class="card"><div class="value">{total}</div>'
            f'<div class="label">Conexiones totales</div></div>'
            f'<div class="card"><div class="value">{blocked}</div>'
            f'<div class="label">Bloqueadas</div></div>'
            f'<div class="card"><div class="value">{tasa:.1f}%</div>'
            f'<div class="label">Tasa de bloqueo</div></div>'
            f'<div class="card"><div class="value">{en_cache}</div>'
            f'<div class="label">IPs en cache (AbuseIPDB)</div></div>'
        )

        with ProxyRequestHandler._sse_lock:
            sync = ProxyRequestHandler._sync_estado
        # "Revisión": si esto no cambió, no cambió nada visible, y entonces no
        # se toca el DOM. Importa más de lo que parece: reemplazar la tabla
        # cerraría las filas de detalle que el usuario tenga abiertas.
        revision = (
            f"{total}|{blocked}|{en_cache}|{filas[0]['id'] if filas else 0}"
            f"|{sync}|{ocultas}"
        )

        return {
            "revision": revision,
            "tarjetas": tarjetas,
            "ruido": self._render_aviso_de_ruido(ocultas),
            "salud": self._render_salud(),
            "historial": self._render_filas_conexiones(filas, consulta),
            "estadisticas": self._render_estadisticas(),
        }

    # ---------- filtro de ruido (telemetría, comprobación, updates) ----------

    def _ocultar_ruido(self) -> bool:
        """¿El panel está tapando la telemetría ahora mismo?"""
        vista = getattr(self, "vista", None)
        return bool(vista is not None and vista.ocultar_ruido)

    def _proceso(self) -> str:
        """Qué programa de esta máquina abrió la conexión que estamos
        atendiendo. El resultado queda cacheado por conexión.

        Se resuelve por el puerto de ORIGEN del cliente, que es lo único que
        identifica de forma única una conexión TCP saliente.

        **Cuándo** se resuelve importa tanto como el cómo, y costó
        descubrirlo: al principio se hacía junto con el registro, que ocurre
        DESPUÉS de responderle al cliente. Para entonces el cliente ya cerró
        su socket, el sistema liberó el puerto, y la tabla de sockets no
        tiene nada: el proceso salía vacío en todas las conexiones HTTP. Por
        eso ahora se resuelve apenas entra el pedido (ver `_marcar_proceso`),
        con el socket todavía vivo, y lo que se registra al final es este
        valor ya guardado.
        """
        cacheado = getattr(self, "_proceso_cache", None)
        if cacheado is not None:
            return cacheado
        lookup = getattr(self, "procesos", None)
        if lookup is None:
            self._proceso_cache = ""
            return ""
        try:
            self._proceso_cache = lookup.nombre_de_puerto(self.client_address[1])
        except Exception:
            self._proceso_cache = ""
        return self._proceso_cache

    def _destino_permitido(self, host: str, port: int) -> tuple[bool, str]:
        """¿Se puede salir hacia este destino, antes de mirar reputación?

        Son dos reglas de política, previas a cualquier lista, y las dos
        existen para que el proxy no se convierta en un pivote de red:

        1. **Puerto.** Un proxy web tiene que tunelizar tráfico web. Dejar
           abrir un túnel a cualquier puerto convierte al proxy en un canal
           TCP arbitrario: sirve para llegar al SSH, al SMB o al RDP de esta
           máquina o de la LAN, y encima queda registrado en el panel como
           una conexión permitida más.
        2. **Destino interno.** Loopback, redes privadas, link-local
           (incluido 169.254.169.254, el servicio de metadatos de las nubes).
           Hoy el proxy escucha solo en loopback, pero `proxy.host` es una
           opción del config: con un 0.0.0.0 esto pasaría a ser un relay
           abierto para toda la red, con acceso directo a los servicios
           locales de la PC, incluido el propio panel.

        Las dos se aflojan juntas con
        `filtering.allow_internal_destinations`, para quien quiera proxear a
        propósito algo de su propia red o en un puerto no estándar.
        """
        if getattr(self.filter_engine, "allow_internal_destinations", False):
            return True, ""
        if port not in PUERTOS_PERMITIDOS:
            permitidos = ", ".join(str(p) for p in sorted(PUERTOS_PERMITIDOS))
            return False, (
                f"puerto {port} no permitido para un tunel (solo {permitidos}): "
                "un proxy web no deberia ser un canal TCP a cualquier lado"
            )
        if _es_destino_interno(host):
            return False, (
                f"destino interno {host}: el proxy no sale hacia loopback, "
                "redes privadas ni link-local"
            )
        return True, ""

    def _es_ruido(self, host: str) -> bool:
        """¿Este destino es ruido de fondo? Se decide UNA vez, al registrar
        la conexión, y queda guardado en la fila.

        Ojo con lo que NO mira: no mira si el filtro está encendido. La marca
        se escribe siempre, para que prender y apagar el filtro sea instantáneo
        y no tenga que recalcular nada sobre todo el historial.
        """
        vista = getattr(self, "vista", None)
        if vista is None:
            return False
        return vista.es_ruidoso(host)

    def _render_aviso_de_ruido(self, ocultas: int) -> str:
        """La línea que dice cuántas conexiones se están escondiendo.

        Existe porque un panel de seguridad que oculta cosas sin decirlo es
        peor que uno saturado: si el número no está a la vista, el usuario
        no tiene forma de saber que los totales no son todo.
        """
        vista = getattr(self, "vista", None)
        if vista is None or not vista.ocultar_ruido:
            return ""
        if not ocultas:
            return (
                '<p class="hint">Filtro de ruido activo '
                f"({vista.cantidad_de_dominios} dominios de telemetría y comprobación). "
                "Todavía no ocultó ninguna conexión.</p>"
            )
        cantidad = f"{ocultas:,}".replace(",", ".")
        return (
            '<p class="hint">Filtro de ruido: <strong>' + cantidad + "</strong> "
            "conexiones de telemetría, comprobación de internet y "
            "actualizaciones están fuera de estos números y de las "
            "estadísticas. Siguen guardadas: buscá el dominio y las ves. "
            'Se apaga desde la pestaña <strong>Configuración</strong>.</p>'
        )

    def _serve_eventos(self, query_string: str) -> None:
        """Canal de eventos (SSE): el servidor deja la respuesta abierta y va
        mandando los fragmentos cuando cambian.

        Por qué SSE y no WebSockets: esto es tráfico en UNA sola dirección
        -el servidor avisa, el navegador muestra- y para eso SSE es HTTP
        común, sin handshake ni enmarcado, así que sale con la librería
        estándar y sin dependencias nuevas. WebSockets serviría para una
        conversación de ida y vuelta, que acá no existe: los botones son
        links normales.

        Reemplaza al `<meta refresh>` de cada 5 segundos, cuyo problema real
        no era la frecuencia sino que recargaba la página entera: te reseteaba
        el scroll, te cerraba los detalles abiertos y te borraba lo que
        estuvieras escribiendo en el buscador.
        """
        base = ProxyRequestHandler
        with base._sse_lock:
            if base._sse_clientes >= self.MAX_CLIENTES_SSE:
                # Sin lugar: se responde 503 y el navegador cae solo al
                # refresco clásico (ver el JS de la página).
                self.send_error(503, "demasiadas pestañas abiertas")
                return
            base._sse_clientes += 1

        consulta = (parse_qs(query_string).get("q") or [""])[0].strip()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            ultima_revision = None
            latido = 0
            while True:
                datos = self._fragmentos(consulta)
                if datos["revision"] != ultima_revision:
                    ultima_revision = datos["revision"]
                    payload = json.dumps(datos, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    latido = 0
                else:
                    latido += 1
                    # Comentario cada ~30s: mantiene viva la conexión y, si el
                    # navegador ya se fue, es lo que lo detecta (falla el
                    # write y se corta el hilo en vez de quedar colgado).
                    if latido >= 6:
                        self.wfile.write(b": latido\n\n")
                        self.wfile.flush()
                        latido = 0
                time.sleep(5)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            # La pestaña se cerró: es lo normal, no un error.
            pass
        finally:
            with base._sse_lock:
                base._sse_clientes -= 1

    # ---------- sincronizar las listas ahora ----------

    # Compartido por todas las conexiones del dashboard: si dos pestañas
    # apretan el botón, la descarga se hace una sola vez.
    _sync_lock = threading.Lock()
    _sync_estado: str = ""

    def _sincronizar_feeds(self) -> None:
        """Fuerza la actualización de las listas de amenazas AHORA, sin
        esperar las 6 horas y sin ir al menú .bat.

        Corre en un hilo aparte y vuelve al panel al instante: bajar tres
        feeds tarda unos segundos y dejar la página colgada mientras tanto
        sería peor que no tener el botón. El resultado aparece solo en el
        panel de salud, que se refresca cada 5 segundos.
        """
        base = ProxyRequestHandler
        with base._sync_lock:
            if base._sync_estado == "corriendo":
                return self._redirect_to_dashboard()
            base._sync_estado = "corriendo"

        engine = self.filter_engine

        def trabajo():
            try:
                import sys as _sys

                from .config_loader import PROJECT_ROOT

                # update_blocklist vive en scripts/, no en el paquete: es el
                # mismo script que corre el .bat y el arranque del proxy, así
                # que no se duplica la lógica de descarga en ningún lado.
                ruta_scripts = str(PROJECT_ROOT / "scripts")
                if ruta_scripts not in _sys.path:
                    _sys.path.insert(0, ruta_scripts)
                import update_blocklist

                update_blocklist.main(force=True)
                engine.blocklist.reload()
                if engine.ip_blocklist is not None:
                    engine.ip_blocklist.reload()
                if engine.allowlist is not None:
                    engine.allowlist.reload()
                resultado = "listo"
            except Exception as exc:  # noqa: BLE001 - nunca tumbar el dashboard
                resultado = f"falló: {exc}"[:200]
            finally:
                with base._sync_lock:
                    base._sync_estado = "" if resultado == "listo" else resultado

        threading.Thread(target=trabajo, daemon=True).start()
        self._redirect_to_dashboard()

    # ---------- historial: filas, detalle y buscador ----------

    def _render_buscador(self, consulta: str, encontradas: int) -> str:
        if consulta:
            resumen = (
                f"<p class='hint'>{encontradas} conexiones que coinciden con "
                f"<strong>{html_lib.escape(consulta)}</strong> (permitidas y bloqueadas). "
                f"<a href='/'>Ver solo los últimos bloqueos</a></p>"
            )
        else:
            resumen = (
                "<p class='hint'>Se muestran los últimos bloqueos. Buscá por IP o "
                "dominio para auditar todo el historial de un destino.</p>"
            )
        return (
            "<form class='add-form' method='get' action='/'>"
            f"<input type='text' name='q' placeholder='buscar por IP o dominio...' "
            f"value='{html_lib.escape(consulta)}'>"
            "<button type='submit'>Buscar</button></form>" + resumen
        )

    def _render_filas_conexiones(self, filas: list[dict], consulta: str) -> str:
        """Cada conexión ocupa dos filas: la visible y una oculta con el
        detalle completo, que se despliega al tocar "Detalle".

        El detalle va embebido en la página en vez de pedirse al servidor
        cuando se hace clic: son 50 filas, pesa nada, y así abre al instante
        sin recargar ni perder la pestaña en la que estabas."""
        if not filas:
            vacio = (
                "No hay conexiones que coincidan con la búsqueda."
                if consulta else "Todavía no se bloqueó ninguna conexión."
            )
            return f"<tr><td colspan='5'>{vacio}</td></tr>"

        partes = []
        for fila in filas:
            host = str(fila["host"] or "")
            bloqueada = bool(fila["blocked"])
            estado = (
                "<span class='pill off-red'>bloqueada</span>" if bloqueada
                else "<span class='pill on'>permitida</span>"
            )
            detalle_id = f"det{fila['id']}"
            # Por qué falta el país: no es lo mismo "no tenés la base
            # descargada" que "esta conexión se cortó antes de resolver el
            # dominio, así que no hay IP para geolocalizar". Decir siempre lo
            # primero manda a descargar algo que capaz ya está descargado.
            destino = str(fila.get("dest_ip") or "")
            if fila.get("country"):
                sin_pais = ""
            elif not destino:
                sin_pais = "no aplica: se bloqueó antes de resolver el dominio"
            elif self.geoip is None or not self.geoip.disponible:
                sin_pais = "sin base de geolocalización (opción 8 del panel .bat)"
            else:
                sin_pais = "esa IP no está en la base"
            campos = (
                ("Fecha y hora", formatear_fecha(fila["timestamp"])),
                ("Host", host),
                ("Puerto", str(fila["port"])),
                ("Método", str(fila["method"] or "")),
                ("Ruta", str(fila["path"] or "-")),
                ("Proceso", str(fila.get("process") or "no identificado")),
                ("Subido", formatear_bytes(fila.get("bytes_out"))),
                ("Bajado", formatear_bytes(fila.get("bytes_in"))),
                ("IP de destino", destino or "no resuelta"),
                ("País", str(fila.get("country") or sin_pais)),
                ("ASN", str(fila.get("asn") or "-")),
                ("Proveedor", str(fila.get("provider") or "-")),
                ("Cliente", str(fila["client_ip"] or "")),
                ("Acción", "bloqueada" if bloqueada else "permitida"),
                ("Motivo", str(fila["reason"] or "sin motivo registrado")),
                ("Tiempo de decisión", f"{float(fila['duration_ms'] or 0):.1f} ms"),
                ("ID en el historial", str(fila["id"])),
            )
            detalle = "".join(
                f"<div class='salud-fila'><span class='salud-nombre'>{html_lib.escape(k)}</span>"
                f"<span class='salud-estado neutro'>{html_lib.escape(v)}</span></div>"
                for k, v in campos
            )
            # En la tabla se muestra el dominio limpio (sin "www."), que es
            # lo que uno lee para distinguir una fila de otra. El host tal
            # cual se conectó sigue completo en el detalle de arriba y en la
            # base: acá se saca un prefijo que se repite en media pantalla.
            visible = limpiar_para_mostrar(host)
            partes.append(
                f"<tr><td>{html_lib.escape(formatear_fecha(fila['timestamp']))}</td>"
                f"<td title='{html_lib.escape(host)}'>{html_lib.escape(visible)}</td>"
                f"<td class='proceso'>{html_lib.escape(str(fila.get('process') or '-'))}</td>"
                f"<td>{estado}</td>"
                f"<td>{html_lib.escape(str(fila['reason'] or '-'))}</td>"
                f"<td class='acciones'>"
                f"<a href=\"javascript:void(0)\" onclick=\"verDetalle('{detalle_id}')\">Detalle</a>"
                f" &middot; <a href=\"/allow?domain={quote(host)}\" "
                f"data-dominio='{html_lib.escape(visible)}' "
                f"onclick=\"return confirmarAccion(this, 'permitir')\">Permitir</a>"
                f"</td></tr>"
                f"<tr id='{detalle_id}' class='detalle-fila'><td colspan='6'>"
                f"<div class='salud'>{detalle}</div></td></tr>"
            )
        return "".join(partes)

    # ---------- exportar ----------

    def _exportar(self, query_string: str, formato: str) -> None:
        """Devuelve el historial como archivo descargable, respetando el
        mismo filtro del buscador: lo que ves es lo que exportás."""
        params = parse_qs(query_string)
        consulta = (params.get("q") or [""])[0].strip()
        try:
            limite = min(int((params.get("limit") or ["5000"])[0]), 50_000)
        except ValueError:
            limite = 5000
        # Respeta también el filtro de ruido, por la misma promesa: si el
        # panel está tapando la telemetría, el archivo tampoco la trae. Para
        # sacarla igual, buscá el dominio (la búsqueda ignora el filtro) o
        # apagá el filtro desde Configuración.
        filas = self.logger_db.buscar(
            texto=consulta, solo_bloqueadas=not consulta, limit=limite,
            ocultar=self._ocultar_ruido(),
        )

        if formato == "json":
            cuerpo = json.dumps(filas, indent=2, ensure_ascii=False).encode("utf-8")
            tipo = "application/json; charset=utf-8"
            nombre = "secureproxy_historial.json"
        else:
            buffer = io.StringIO()
            escritor = csv.DictWriter(buffer, fieldnames=list(LoggerDB.COLUMNAS))
            escritor.writeheader()
            escritor.writerows(filas)
            # utf-8-sig (con BOM) para que Excel en Windows no rompa los
            # acentos al abrir el CSV directo.
            cuerpo = buffer.getvalue().encode("utf-8-sig")
            tipo = "text/csv; charset=utf-8"
            nombre = "secureproxy_historial.csv"

        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Disposition", f'attachment; filename="{nombre}"')
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    # ---------- panel de salud de las fuentes ----------

    def _render_salud(self) -> str:
        """Estado de cada fuente de amenazas y cuándo se sincronizó.

        Es la pregunta que uno se hace cada tanto y hasta ahora no se podía
        contestar sin mirar archivos a mano: ¿las listas están frescas, o
        hace tres días que una fuente viene fallando y no me enteré?
        """
        from .config_loader import PROJECT_ROOT

        filas = []

        def fila(nombre: str, ok: bool, estado: str, detalle: str = "") -> None:
            icono = "&#10004;" if ok else "&#10007;"
            clase = "ok" if ok else "mal"
            extra = f"<span class='salud-detalle'>{html_lib.escape(detalle)}</span>" if detalle else ""
            filas.append(
                f"<div class='salud-fila'><span class='salud-nombre'>{html_lib.escape(nombre)}</span>"
                f"<span class='salud-estado {clase}'>{icono} {html_lib.escape(estado)}</span>{extra}</div>"
            )

        # Feeds de descarga (URLhaus, OpenPhish, Feodo Tracker).
        guardado = feeds_status.leer(PROJECT_ROOT / "data")
        ultima_sync = ""

        # Respaldo para cuando todavía no hay estado por fuente: la fecha del
        # archivo de listas. Pasa en toda instalación que ya venía andando de
        # antes de que esta pantalla existiera -las listas están ahí y son
        # válidas, pero nadie anotó de dónde salió cada una-. Decir "sin
        # datos" ahí sería mentir por omisión: lo honesto es mostrar que la
        # lista está cargada y aclarar que el detalle por fuente aparece
        # desde la próxima actualización.
        def rutas_de(lista) -> list:
            # ip_blocklist y allowlist son opcionales en el motor: el panel no
            # puede asumir que están.
            return list(getattr(lista, "paths", []) or [])

        archivos = {
            "URLhaus": rutas_de(self.filter_engine.blocklist),
            "OpenPhish": rutas_de(self.filter_engine.blocklist),
            "Feodo Tracker": rutas_de(self.filter_engine.ip_blocklist),
        }

        def fecha_del_archivo(nombre: str) -> float:
            for ruta in archivos.get(nombre, []):
                try:
                    if ruta.exists() and "feeds" in ruta.name:
                        return ruta.stat().st_mtime
                except OSError:
                    continue
            return 0.0

        # FireHOL entraba en feeds_status pero no se mostraba: una caída
        # sostenida de esa fuente era justamente el caso que este panel dice
        # cubrir, y pasaba invisible.
        for nombre in ("URLhaus", "OpenPhish", "Feodo Tracker", "FireHOL"):
            datos = guardado.get(nombre)
            if not datos:
                mtime = fecha_del_archivo(nombre)
                if mtime:
                    fila(nombre, True, f"lista cargada {hace_cuanto(mtime)}",
                         "el estado por fuente se registra desde la próxima actualización")
                else:
                    fila(nombre, False, "sin datos",
                         "corré 'Actualizar listas' (opción 4 del panel .bat)")
                continue
            ok = bool(datos.get("ok"))
            cuando = hace_cuanto(datos.get("ultimo_ok"))
            entradas = datos.get("entradas", 0)
            if ok:
                fila(nombre, True, f"OK {cuando}", f"{entradas:,} reglas".replace(",", ".")
                     if entradas != 1 else "1 regla")
            else:
                fila(nombre, False, "falló", f"última buena {cuando}: {datos.get('error', '')}")
            if datos.get("ultimo_ok", "") > ultima_sync:
                ultima_sync = datos.get("ultimo_ok", "")

        # AbuseIPDB: sin key, circuito abierto, o funcionando.
        abuse = self.filter_engine.abuseipdb_client.estado()
        if abuse["ok"]:
            ultimo = abuse["ultimo_ok"]
            fila("AbuseIPDB", True, "OK",
                 f"última consulta {hace_cuanto(ultimo)}" if ultimo else "sin consultas todavía")
        else:
            fila("AbuseIPDB", False, abuse["motivo"], abuse.get("ayuda", ""))

        # TOR: lista en memoria, se baja sola cada 6 horas.
        tor = self.filter_engine.tor_list.estado()
        if not self.filter_engine.check_tor_exit_nodes:
            fila("Lista de nodos TOR", False, "desactivado", "se puede activar en Configuración")
        elif tor["ok"]:
            fila("Lista de nodos TOR", True, f"OK {hace_cuanto(tor['ultimo_ok'])}",
                 f"{tor['nodos']:,} nodos".replace(",", "."))
        else:
            fila("Lista de nodos TOR", False, "sin lista",
                 f"último intento {hace_cuanto(tor['ultimo_intento'])}")

        alertas = getattr(self, "alertas", None)
        if alertas is not None:
            estado_alertas = alertas.estado()
            fila("Avisos en el escritorio", estado_alertas["ok"],
                 estado_alertas["motivo"], estado_alertas["ayuda"])

        procesos = getattr(self, "procesos", None)
        if procesos is not None:
            fila("Identificación de procesos", procesos.disponible,
                 "activa" if procesos.disponible else "no disponible",
                 "" if procesos.disponible else "no se puede leer la tabla de sockets")

        reglas = len(self.filter_engine.blocklist._domains)
        if not ultima_sync:
            # Sin estado por fuente, la fecha del archivo de listas es la
            # mejor respuesta disponible, y es una respuesta de verdad.
            respaldo = max((fecha_del_archivo(n) for n in archivos), default=0.0)
            if respaldo:
                from datetime import datetime as _dt

                ultima_sync = _dt.fromtimestamp(respaldo, timezone.utc).isoformat()
        version = (ultima_sync[:10].replace("-", ".") if ultima_sync else "sin sincronizar")
        pie = (
            f"<div class='salud-fila'><span class='salud-nombre'>Última sincronización</span>"
            f"<span class='salud-estado neutro'>{html_lib.escape(formatear_fecha(ultima_sync)) if ultima_sync else 'nunca'}</span></div>"
            f"<div class='salud-fila'><span class='salud-nombre'>Versión de reglas</span>"
            f"<span class='salud-estado neutro'>{version}</span>"
            f"<span class='salud-detalle'>{reglas:,} dominio{'s' if reglas != 1 else ''} cargado{'s' if reglas != 1 else ''}</span></div>".replace(",", ".")
        )
        with ProxyRequestHandler._sync_lock:
            sync = ProxyRequestHandler._sync_estado
        if sync == "corriendo":
            aviso = ("<div class='sync-aviso'>Sincronizando las listas ahora... "
                     "el panel se actualiza solo cuando termine.</div>")
        elif sync:
            aviso = f"<div class='sync-aviso mal'>{html_lib.escape(sync)}</div>"
        else:
            aviso = ""
        return f"<div class='salud'><h2>Salud del sistema</h2>{aviso}{''.join(filas)}{pie}</div>"

    # ---------- estadísticas ----------

    def _barras(
        self, datos: list[tuple[str, int]], titulo: str, vacio: str,
        investigables: bool = False,
    ) -> str:
        """Gráfico de barras hecho con divs: sin librerías ni JavaScript.

        Un gráfico de verdad traería una dependencia entera para mostrar diez
        números; con el ancho proporcional al máximo se lee igual de bien.

        `investigables=True` convierte cada etiqueta en un link a Consultar.
        Es donde uno mira cuando quiere saber qué es un destino, así que
        tiene que poder preguntarlo desde ahí mismo.
        """
        if not datos:
            return f"<h2>{titulo}</h2><p class='empty'>{vacio}</p>"
        tope = max(valor for _, valor in datos) or 1

        def etiqueta_html(texto: str) -> str:
            visible = html_lib.escape(str(texto))
            if not investigables:
                return f"<span class='barra-label' title='{visible}'>{visible}</span>"
            return (
                f"<a class='barra-label' title='Consultar {visible}' "
                f"href='/osint?osint={quote(str(texto))}'>{visible}</a>"
            )

        filas = "".join(
            f"<div class='barra-fila'>"
            f"{etiqueta_html(etiqueta)}"
            f"<span class='barra-track'><span class='barra-fill' style='width:{valor / tope * 100:.1f}%'></span></span>"
            f"<span class='barra-valor'>{valor}</span></div>"
            for etiqueta, valor in datos
        )
        return f"<h2>{titulo}</h2><div class='barras'>{filas}</div>"

    def _render_estadisticas(self) -> str:
        ocultos = self._ocultar_ruido()
        # Ya viene de la más vieja a la más nueva, que es como se lee un
        # gráfico de tiempo, y con la ventana cortada por tiempo real: así
        # cada hora aparece una sola vez.
        por_hora = self.logger_db.por_hora(horas=24, ocultar=ocultos)
        horas = [(hora_local(h), total) for h, total, _bloq in por_hora]
        bloqueadas_hora = [(hora_local(h), bloq) for h, _total, bloq in por_hora if bloq]
        aviso = ""
        if ocultos:
            aviso = (
                " Los dominios de telemetría, comprobación de internet y "
                "actualizaciones están fuera de estos números: se pueden "
                "volver a incluir desde Configuración."
            )
        return (
            "<p class='hint'>Todo esto sale de las mismas conexiones que ya se "
            f"registran: son consultas al historial, no un registro aparte.{aviso}</p>"
            + self._barras(horas, "Conexiones por hora (últimas 24)",
                           "Todavía no hay conexiones registradas.")
            + self._barras(bloqueadas_hora, "Bloqueos por hora",
                           "No hubo bloqueos en las últimas horas.")
            + self._barras(
                [(limpiar_para_mostrar(h), c)
                 for h, c in self.logger_db.top_hosts(limit=10, ocultar=ocultos)],
                "Top 10 de destinos", "Sin datos todavía.", investigables=True)
            + self._barras(self.logger_db.top_paises(limit=10, ocultar=ocultos),
                           "Destinos por país",
                           "Sin datos de país todavía (corré scripts/update_geoip.py "
                           "para descargar la base).")
            + self._barras(self.logger_db.bloqueos_por_motivo(limit=10, ocultar=ocultos),
                           "Bloqueos por motivo",
                           "Todavía no se bloqueó ninguna conexión.")
            + self._render_sostenidas()
            + self._render_beaconing()
            + self._render_volumen()
        )

    def _render_beaconing(self) -> str:
        """Destinos con los que se habla con regularidad de reloj.

        Es una detección distinta de la de "destinos insistentes", y la
        diferencia vale explicarla en pantalla: aquella mira CUÁNTO y agarra
        mineros, esta mira CADA CUÁNTO y agarra implantes de
        comando-y-control, que se conectan poco justamente para no llamar
        la atención por volumen.
        """
        filas = self.logger_db.beaconing(horas=24, ocultar=self._ocultar_ruido())
        encabezado = (
            "<h2>Conexiones con ritmo de reloj (posible C2)</h2>"
            "<p class='hint'>Destinos con los que se habla a intervalos casi "
            "exactos. Una persona navegando nunca da esto; un programa "
            "preguntando \"¿hay órdenes nuevas?\" da exactamente esto. Es la "
            "firma de un implante de comando-y-control, y también la de un "
            "cliente de correo o de mensajería revisando cada tanto, así que "
            "acá no se bloquea nada: mirá el proceso de la última columna, "
            "que es lo que te dice cuál de las dos cosas es.</p>"
        )
        if not filas:
            return encabezado + (
                "<p class='empty'>Ningún destino con un ritmo lo bastante "
                "regular en las últimas 24 horas.</p>"
            )
        cuerpo = "".join(
            f"<tr><td title='{html_lib.escape(str(host))}'>"
            f"{html_lib.escape(limpiar_para_mostrar(str(host)))}</td>"
            f"<td>{cantidad}</td>"
            f"<td>cada {_intervalo_legible(promedio)}</td>"
            f"<td>{jitter * 100:.1f}%</td>"
            f"<td class='proceso'>{html_lib.escape(proceso or '-')}</td>"
            f"<td><a href=\"/osint?osint={quote(str(host))}\">Investigar</a></td></tr>"
            for host, cantidad, promedio, jitter, proceso in filas
        )
        return (
            encabezado
            + "<table><tr><th>Destino</th><th>Conexiones</th><th>Cada</th>"
            f"<th>Variación</th><th>Proceso</th><th></th></tr>{cuerpo}</table>"
        )

    def _render_volumen(self) -> str:
        """Adónde se subieron más datos.

        Es la única señal de exfiltración que un proxy puede dar sin romper
        el TLS: el contenido va cifrado, pero cuánto se movió y para qué lado
        se ve igual. Se mira lo SUBIDO, no lo bajado: bajar mucho es ver un
        video, subir mucho a un destino raro es otra cosa.
        """
        filas = self.logger_db.top_por_volumen(limit=10, ocultar=self._ocultar_ruido())
        encabezado = (
            "<h2>Adónde subiste más datos (últimas 24 horas)</h2>"
            "<p class='hint'>El proxy no puede leer lo que va adentro de una "
            "conexión HTTPS, pero sí cuánto pesó y para qué lado fue. Subir "
            "mucho a un destino que no reconocés es la señal de exfiltración "
            "que se puede ver sin descifrar nada.</p>"
        )
        if not filas:
            return encabezado + "<p class='empty'>Todavía no hay volumen registrado.</p>"
        cuerpo = "".join(
            f"<tr><td title='{html_lib.escape(str(host))}'>"
            f"{html_lib.escape(limpiar_para_mostrar(str(host)))}</td>"
            f"<td>{formatear_bytes(subidos)}</td>"
            f"<td>{formatear_bytes(bajados)}</td>"
            f"<td class='proceso'>{html_lib.escape(proceso or '-')}</td>"
            f"<td><a href=\"/osint?osint={quote(str(host))}\">Investigar</a></td></tr>"
            for host, subidos, bajados, proceso in filas
        )
        return (
            encabezado
            + "<table><tr><th>Destino</th><th>Subido</th><th>Bajado</th>"
            f"<th>Proceso</th><th></th></tr>{cuerpo}</table>"
        )

    def _render_sostenidas(self) -> str:
        """Destinos machacados una y otra vez en las últimas horas.

        Es la forma de detectar un minero sin mirar el contenido de la
        conexión, que va cifrado: un navegador reparte sus conexiones entre
        muchos destinos, un minero martilla siempre el mismo pool. Esto NO
        bloquea nada: señala para que vayas a mirar qué proceso es.
        """
        filas = self.logger_db.conexiones_sostenidas(
            minimo=30, horas=6, ocultar=self._ocultar_ruido()
        )
        if not filas:
            return (
                "<h2>Destinos insistentes (últimas 6 horas)</h2>"
                "<p class='empty'>Nada llamativo: ningún destino con más de 30 "
                "conexiones. Acá aparecería, por ejemplo, un minero de "
                "criptomonedas golpeando siempre el mismo pool.</p>"
            )
        filas_html = "".join(
            f"<tr><td title='{html_lib.escape(str(host))}'>"
            f"{html_lib.escape(limpiar_para_mostrar(str(host)))}</td><td>{cantidad}</td>"
            f"<td>{html_lib.escape(formatear_fecha(primera))}</td>"
            f"<td>{html_lib.escape(formatear_fecha(ultima))}</td>"
            f"<td><a href=\"/osint?osint={quote(str(host))}\">Investigar</a></td></tr>"
            for host, cantidad, primera, ultima in filas
        )
        return (
            "<h2>Destinos insistentes (últimas 6 horas)</h2>"
            "<p class='hint'>Muchas conexiones al mismo lugar sostenidas en el "
            "tiempo. Puede ser algo normal -un servicio de sincronización, una "
            "pestaña con streaming- o un minero de criptomonedas. Esto no "
            "bloquea nada: te avisa dónde mirar.</p>"
            "<table><tr><th>Destino</th><th>Conexiones</th><th>Primera</th>"
            f"<th>Última</th><th></th></tr>{filas_html}</table>"
        )

    # ---------- OSINT manual ----------

    def _render_osint(self, consulta: str) -> str:
        """Consulta a mano un dominio o IP contra TODO lo que el proxy sabe.

        Responde dos cosas distintas a propósito: qué dice cada fuente por
        separado, y qué haría el proxy con esa conexión ahora mismo. La
        segunda es la que importa cuando estás depurando un falso positivo.
        """
        formulario = (
            "<form class='add-form' method='get' action='/osint'>"
            f"<input type='text' name='osint' placeholder='ejemplo.com o 8.8.8.8' "
            f"value='{html_lib.escape(consulta)}' required>"
            "<button class='ok-btn' type='submit'>Consultar</button></form>"
            "<p class='hint'>Consulta en vivo contra las listas locales, la "
            "lista de nodos TOR y AbuseIPDB. No queda registrado como una "
            "conexión: es solo una consulta.</p>"
        )
        if not consulta:
            return formulario

        motor = self.filter_engine
        from .threat_intel import resolve_host_to_ip

        limpio, avisos_norm = normalizar_dominio(consulta)
        nota = ""
        if limpio and limpio != consulta.strip().lower():
            nota = (
                f"<p class='hint'>Se consultó <strong>{html_lib.escape(limpio)}</strong>: "
                + html_lib.escape("; ".join(avisos_norm)) + ".</p>"
            )
            consulta = limpio

        es_ip = consulta.replace(".", "").isdigit()
        ip = consulta if es_ip else resolve_host_to_ip(consulta)

        lineas = []

        def dato(nombre: str, valor: str, malo: bool = False) -> None:
            clase = "mal" if malo else "ok"
            lineas.append(
                f"<div class='salud-fila'><span class='salud-nombre'>{html_lib.escape(nombre)}</span>"
                f"<span class='salud-estado {clase}'>{html_lib.escape(valor)}</span></div>"
            )

        if not es_ip:
            dato("IP resuelta", ip or "no resuelve", malo=not ip)
            en_blanca = bool(motor.allowlist and motor.allowlist.is_allowed(consulta))
            dato("En lista blanca", "sí" if en_blanca else "no", malo=False)
            dato("En lista negra", "sí" if motor.blocklist.is_blocked(consulta) else "no",
                 malo=motor.blocklist.is_blocked(consulta))
        if ip:
            en_ips = bool(motor.ip_blocklist and motor.ip_blocklist.is_blocked(ip))
            dato("IP en lista de C2 (Feodo)", "sí" if en_ips else "no", malo=en_ips)
            es_tor = motor.tor_list.is_tor_exit_node(ip)
            dato("Nodo de salida TOR", "sí" if es_tor else "no", malo=es_tor)
            score = motor.abuseipdb_client.get_abuse_score(ip)
            dato("Score de AbuseIPDB", f"{score} / 100 (umbral: {motor.abuseipdb_min_score})",
                 malo=score >= motor.abuseipdb_min_score)

        decision = motor.evaluate(consulta if not es_ip else consulta)
        if decision.blocked:
            veredicto = f"<div class='veredicto mal'>SE BLOQUEA - {html_lib.escape(decision.reason)}</div>"
        elif getattr(decision, "would_have_blocked", False):
            veredicto = (
                f"<div class='veredicto aviso'>SE PERMITE, pero en modo enforce se "
                f"bloquearía - {html_lib.escape(decision.reason)}</div>"
            )
        else:
            veredicto = "<div class='veredicto ok'>SE PERMITE - no matchea ninguna regla</div>"

        return (
            formulario
            + nota
            + f"<h2>Resultado para {html_lib.escape(consulta)}</h2>"
            + veredicto
            + f"<div class='salud'>{''.join(lineas)}</div>"
            + self._render_acciones_osint(consulta, es_ip)
        )

    def _render_acciones_osint(self, destino: str, es_ip: bool) -> str:
        """Qué podés HACER con lo que acabás de mirar.

        Sin esto, investigar terminaba en un callejón sin salida: el panel te
        decía "se permite, todo bien" y te dejaba sin nada para hacer, así
        que había que ir a otra pestaña y volver a escribir el dominio. Las
        tres acciones son las tres respuestas posibles a "¿y esto qué es?":
        es peligroso (bloquear), es mío y confío (permitir), o es ruido de
        fondo que no quiero volver a ver (ocultar del panel).

        La tercera es la que no existía en ningún lado y es la que más se
        usa: la lista de ruido que viene de fábrica cubre el ruido de
        sistema, no las aplicaciones de cada uno.
        """
        if es_ip:
            # Las listas son por dominio; para una IP suelta no hay acción
            # que ofrecer sin mentir sobre lo que haría.
            return ""

        motor = self.filter_engine
        vista = getattr(self, "vista", None)
        en_negra = destino in motor.blocklist.manual_entries()
        en_blanca = bool(motor.allowlist and destino in motor.allowlist.manual_entries())
        es_ruido = bool(vista and vista.es_ruidoso(destino))
        d = quote(destino)
        visible = html_lib.escape(destino)

        botones = []
        if en_negra:
            botones.append(
                f"<form method='get' action='/unblockdomain'>"
                f"<input type='hidden' name='domain' value='{visible}'>"
                f"<button type='submit'>Sacar de la lista negra</button></form>"
            )
        else:
            botones.append(
                f"<form method='get' action='/blockdomain' data-dominio='{visible}' "
                f"onsubmit=\"return confirmarAccion(this, 'bloquear')\">"
                f"<input type='hidden' name='domain' value='{visible}'>"
                f"<button class='danger-btn' type='submit'>Bloquear siempre</button></form>"
            )
        if en_blanca:
            botones.append(
                f"<form method='get' action='/unallow'>"
                f"<input type='hidden' name='domain' value='{visible}'>"
                f"<button type='submit'>Sacar de la lista blanca</button></form>"
            )
        else:
            botones.append(
                f"<form method='get' action='/allow' data-dominio='{visible}' "
                f"onsubmit=\"return confirmarAccion(this, 'permitir-siempre')\">"
                f"<input type='hidden' name='domain' value='{visible}'>"
                f"<button class='ok-btn' type='submit'>Permitir siempre</button></form>"
            )
        if vista is not None:
            if es_ruido:
                botones.append(
                    f"<form method='get' action='/mostrar'>"
                    f"<input type='hidden' name='domain' value='{visible}'>"
                    f"<button type='submit'>Volver a mostrarlo en el panel</button></form>"
                )
            else:
                botones.append(
                    f"<form method='get' action='/ocultar' data-dominio='{visible}' "
                    f"onsubmit=\"return confirmarAccion(this, 'ocultar')\">"
                    f"<input type='hidden' name='domain' value='{visible}'>"
                    f"<button type='submit'>Ocultar del panel</button></form>"
                )
        _ = d
        return (
            "<h2>Qué hacer con esto</h2>"
            "<p class='hint'>Bloquear y permitir cambian lo que el proxy DEJA "
            "PASAR. Ocultar del panel no toca nada de eso: solo saca el dominio "
            "de la vista, para cuando es ruido de fondo de una aplicación tuya "
            "y te tapa lo demás.</p>"
            f"<div class='acciones-barra acciones-osint'>{''.join(botones)}</div>"
        )

    @property
    def _query_actual(self) -> dict:
        """Parámetros de la URL con la que se pidió el dashboard: la búsqueda
        del historial y la consulta OSINT viajan por ahí."""
        return parse_qs(urlsplit(self.path).query)

    def _serve_dashboard(self) -> None:
        # Búsqueda sobre el historial. Con texto se muestran TODAS las
        # conexiones que matchean (permitidas y bloqueadas), porque auditar
        # una IP es querer ver todo lo que hizo, no solo lo que se le cortó.
        consulta = (self._query_actual.get("q") or [""])[0].strip()
        # Los mismos fragmentos que despues manda el canal de eventos: la
        # primera carga y las actualizaciones salen del mismo codigo, asi no
        # se pueden ir separando con el tiempo.
        frag = self._fragmentos(consulta)
        tarjetas_html = frag["tarjetas"]
        ruido_html = frag["ruido"]
        # Aviso de una acción que acaba de pasar (por ejemplo: "se guardó
        # como ejemplo.com, se sacó el www."). Viene por la URL del redirect
        # y se muestra una sola vez; no forma parte de los fragmentos que
        # refresca el canal de eventos, justamente para que no quede pegado.
        aviso = (self._query_actual.get("aviso") or [""])[0].strip()
        aviso_html = (
            f"<p class='aviso-accion'>{html_lib.escape(aviso)}</p>" if aviso else ""
        )
        rows_html = frag["historial"]
        salud_html = frag["salud"]
        estadisticas_html = frag["estadisticas"]
        buscador = self._render_buscador(consulta, rows_html.count("<tr><td>"))
        osint_html = self._render_osint((self._query_actual.get("osint") or [""])[0].strip())

        allowlist_html = self._render_editable_list(
            self.filter_engine.allowlist.manual_entries(), "/unallow"
        )
        blocklist_html = self._render_editable_list(
            self.filter_engine.blocklist.manual_entries(), "/unblockdomain"
        )

        config_html = self._render_config_panel()

        # El botón de apagado solo aparece si este proceso realmente se puede
        # apagar. Cuando el proxy está embebido en otro programa (o en los
        # tests) no hay a quién avisarle, y un botón que no hace nada es peor
        # que no tenerlo.
        if callable(type(self).apagar):
            apagar_html = (
                "<form method=\"get\" action=\"/apagar\" "
                "onsubmit=\"return confirmarApagado()\">"
                "<button type=\"submit\" class=\"apagar-btn\">Apagar proxy</button>"
                "</form>"
            )
        else:
            apagar_html = ""

        page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
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
  .hint {{ color:#9aa0a6; font-size:0.82rem; }}
  code {{ background:#1a1d24; padding:0.1rem 0.35rem; border-radius:4px; }}
  h2 {{ margin-top:1.6rem; margin-bottom:0.3rem; }}
  /* Tarjetas de opción: se ve de un vistazo cuál está activa. */
  .opciones {{ display:flex; gap:0.9rem; flex-wrap:wrap; margin:0.9rem 0 0.4rem; }}
  .optcard {{ flex:1 1 260px; background:#161922; border:1px solid #2a2e37; border-radius:10px; padding:0.9rem 1rem; }}
  .optcard.activa {{ border-color:#3f7d52; background:#16241a; }}
  .optcard-head {{ display:flex; align-items:baseline; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.35rem; }}
  .optcard-title {{ font-size:1rem; font-weight:600; }}
  .optcard-sub {{ font-size:0.75rem; color:#9aa0a6; text-transform:uppercase; letter-spacing:0.04em; }}
  .optcard .hint {{ margin:0 0 0.7rem; line-height:1.45; }}
  .optcard button {{ width:100%; }}
  .badge-activo {{ display:inline-block; background:#1e3a26; color:#7bd88f; border-radius:6px; padding:0.4rem 0.8rem; font-size:0.85rem; }}
  /* Interruptores: estado a la izquierda, acción a la derecha. */
  .fila-switch {{ display:flex; align-items:center; gap:0.75rem; margin:0.6rem 0 0.2rem; flex-wrap:wrap; }}
  .pill {{ display:inline-block; border-radius:999px; padding:0.25rem 0.75rem; font-size:0.78rem; font-weight:600; letter-spacing:0.02em; }}
  .pill.on {{ background:#1e3a26; color:#7bd88f; }}
  .pill.off {{ background:#24262e; color:#9aa0a6; }}
  .leyenda {{ color:#9aa0a6; font-size:0.85rem; }}
  button:hover {{ filter:brightness(1.25); }}
  button {{ transition:filter 0.15s ease; }}
  .add-form input[type=number] {{ background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; width:110px; }}
  a {{ color:#7fb2ff; }}
  a.danger {{ color:#ff8a8a; }}
  .tabs {{ display:flex; gap:0.5rem; margin-top:1.5rem; border-bottom:1px solid #2a2e37; }}
  /* border-radius:0 explícito: las pestañas son <button> y heredaban el
     redondeo de la regla general, lo que curvaba las puntas de la línea
     azul del subrayado. Acá la línea tiene que ser recta. */
  .tab-btn {{ background:none; border:none; border-radius:0; color:#9aa0a6; font-size:0.9rem; font-family:inherit; padding:0.6rem 1rem; cursor:pointer; border-bottom:2px solid transparent; }}
  .tab-btn.active {{ color:#e6e6e6; border-bottom:2px solid #7fb2ff; }}
  .tab-panel {{ display:none; padding-top:1rem; }}
  .tab-panel.active {{ display:block; }}
  .add-form {{ display:flex; gap:0.5rem; margin-bottom:1rem; }}
  .add-form input[type=text] {{ flex:1; background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; }}
  button {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; font-size:0.85rem; font-family:inherit; }}
  button.ok-btn {{ background:#1e3a26; color:#7bd88f; }}
  button.danger-btn {{ background:#3a1f22; color:#ff8a8a; }}
  /* Apagar no es "una acción destructiva más": deja la máquina sin filtrado.
     Va con borde para que se distinga de Borrar cache, que está al lado y
     tiene consecuencias mucho menores. */
  button.apagar-btn {{ background:#2b1416; color:#ff7b72; border:1px solid #6b2a2a; }}
  button.apagar-btn:hover {{ background:#3d1a1d; }}
  /* Barra de acciones: alineada a la derecha, entre las tarjetas y la tabla. */
  .acciones-barra {{ display:flex; gap:0.5rem; justify-content:flex-end; margin:-0.5rem 0 0.5rem; flex-wrap:wrap; }}
  .acciones-barra form {{ margin:0; }}
  /* Panel de salud: dos columnas, nombre a la izquierda y estado a la derecha. */
  .salud {{ background:#161922; border:1px solid #2a2e37; border-radius:10px; padding:0.9rem 1.1rem; margin:1rem 0; }}
  .salud h2 {{ margin:0 0 0.6rem; }}
  .salud-fila {{ display:flex; align-items:baseline; gap:0.75rem; padding:0.28rem 0; font-size:0.86rem; flex-wrap:wrap; }}
  .salud-nombre {{ min-width:190px; color:#9aa0a6; }}
  .salud-estado {{ font-family:Consolas,"Courier New",monospace; }}
  .salud-estado.ok {{ color:#7bd88f; }}
  .salud-estado.mal {{ color:#ff8a8a; }}
  .salud-estado.neutro {{ color:#e6e6e6; }}
  .salud-detalle {{ color:#6f757e; font-size:0.8rem; }}
  .sync-aviso {{ background:#2a2411; border:1px solid #3d3316; color:#e6d08a; border-radius:6px; padding:0.45rem 0.7rem; margin:0 0 0.6rem; font-size:0.82rem; }}
  .sync-aviso.mal {{ background:#2a1618; border-color:#3a1f22; color:#ffb3b3; }}
  /* Gráfico de barras sin librerías: el ancho es proporcional al máximo. */
  .barras {{ margin:0.5rem 0 1.2rem; }}
  .barra-fila {{ display:flex; align-items:center; gap:0.6rem; padding:0.15rem 0; font-size:0.82rem; }}
  .barra-label {{ width:210px; color:#9aa0a6; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .barra-track {{ flex:1; background:#1a1d24; border-radius:4px; height:14px; overflow:hidden; }}
  .barra-fill {{ display:block; height:100%; background:#3f6ea8; }}
  .barra-valor {{ width:60px; text-align:right; color:#e6e6e6; font-family:Consolas,monospace; }}
  /* Fila de detalle: oculta hasta que se toca "Detalle". */
  .detalle-fila {{ display:none; }}
  .detalle-fila.abierta {{ display:table-row; }}
  .detalle-fila .salud {{ margin:0.3rem 0; }}
  .acciones a {{ white-space:nowrap; }}
  .pill.off-red {{ background:#3a1f22; color:#ff8a8a; }}
  .veredicto {{ border-radius:8px; padding:0.7rem 1rem; margin:0.8rem 0; font-weight:600; font-size:0.9rem; }}
  .veredicto.ok {{ background:#16241a; border:1px solid #1e3a26; color:#b7e3c2; }}
  .veredicto.mal {{ background:#2a1618; border:1px solid #3a1f22; color:#ffb3b3; }}
  .veredicto.aviso {{ background:#2a2411; border:1px solid #3d3316; color:#e6d08a; }}
  .acciones-osint {{ justify-content:flex-start; margin-top:0.4rem; }}
  .proceso {{ font-family:ui-monospace, Consolas, monospace; font-size:0.82rem; color:#c9d1d9; }}
  .plegable {{ margin:0.6rem 0 1rem 0; }}
  .plegable > summary {{ cursor:pointer; color:#7fb2ff; font-size:0.9rem;
                         padding:0.3rem 0; user-select:none; }}
  .aviso-accion {{ background:#132a1c; border:1px solid #1e4630; color:#a7e0bd;
                   border-radius:8px; padding:0.7rem 0.9rem; margin:0 0 1rem 0;
                   font-size:0.9rem; }}
</style>
</head>
<body>
  <h1>SecureProxy</h1>
  <p class="subtitle">Panel de control - <span id="estado-vivo">en vivo</span></p>
  {aviso_html}
  <div class="stats" id="tarjetas">{tarjetas_html}</div>
  <div id="ruido">{ruido_html}</div>

  <div class="acciones-barra">
    <button type="button" onclick="exportar()">Exportar</button>
    <form method="get" action="/sincronizar" onsubmit="return confirm('¿Actualizar ahora las listas de amenazas? Se descargan URLhaus, OpenPhish, Feodo Tracker y FireHOL sin esperar el ciclo de 6 horas.')">
      <button type="submit" class="ok-btn">Sincronizar listas</button>
    </form>
    <form method="get" action="/clear-cache" onsubmit="return confirm('¿Borrar el cache de reputación de IPs?')">
      <button type="submit" class="danger-btn">Borrar cache</button>
    </form>
    {apagar_html}
  </div>

  <div id="salud">{salud_html}</div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="bloqueos" onclick="showTab('bloqueos', this)">Historial</button>
    <button class="tab-btn" data-tab="stats" onclick="showTab('stats', this)">Estadísticas</button>
    <button class="tab-btn" data-tab="osint" onclick="showTab('osint', this)">Consultar</button>
    <button class="tab-btn" data-tab="blanca" onclick="showTab('blanca', this)">Lista blanca</button>
    <button class="tab-btn" data-tab="negra" onclick="showTab('negra', this)">Lista negra (manual)</button>
    <button class="tab-btn" data-tab="config" onclick="showTab('config', this)">Configuración</button>
  </div>

  <div id="tab-bloqueos" class="tab-panel active">
    <h2>Historial de conexiones</h2>
    {buscador}
    <table>
      <tr><th>Fecha y hora</th><th>Host</th><th>Proceso</th><th>Estado</th><th>Motivo</th><th>Acciones</th></tr>
      <tbody id="historial">{rows_html}</tbody>
    </table>
  </div>

  <div id="tab-stats" class="tab-panel">
    <h2>Estadísticas</h2>
    <div id="estadisticas">{estadisticas_html}</div>
  </div>

  <div id="tab-osint" class="tab-panel">
    <h2>Consultar un dominio o una IP</h2>
    {osint_html}
  </div>

  <div id="tab-blanca" class="tab-panel">
    <h2>Lista blanca</h2>
    <p class="empty">Un dominio acá gana por sobre blocklist, TOR y AbuseIPDB.</p>
    <p class="hint">Podés pegar la URL entera de la barra del navegador: se le saca el <code>https://</code>, el <code>www.</code>, el puerto y todo lo que venga después de la barra, y se guarda el dominio limpio. La regla cubre el dominio y sus subdominios.<br>El camino (<code>/una-seccion</code>) no se puede filtrar: en HTTPS el proxy solo ve el dominio, el resto viaja cifrado adentro del túnel. Por eso se bloquea el sitio entero.</p>
    <form class="add-form" method="get" action="/allow">
      <input type="text" name="domain" placeholder="ejemplo.com o https://www.ejemplo.com/algo" required>
      <button type="submit">Agregar</button>
    </form>
    {allowlist_html}
  </div>

  <div id="tab-negra" class="tab-panel">
    <h2>Lista negra (manual)</h2>
    <p class="empty">Solo la lista manual (data/blocklist.txt). Lo generado por
    URLhaus/OpenPhish/Feodo Tracker no se administra desde acá.</p>
    <p class="hint">Podés pegar la URL entera de la barra del navegador: se le saca el <code>https://</code>, el <code>www.</code>, el puerto y todo lo que venga después de la barra, y se guarda el dominio limpio. La regla cubre el dominio y sus subdominios.<br>El camino (<code>/una-seccion</code>) no se puede filtrar: en HTTPS el proxy solo ve el dominio, el resto viaja cifrado adentro del túnel. Por eso se bloquea el sitio entero.</p>
    <form class="add-form" method="get" action="/blockdomain">
      <input type="text" name="domain" placeholder="ejemplo.com o https://www.ejemplo.com/algo" required>
      <button type="submit">Agregar</button>
    </form>
    {blocklist_html}
  </div>

  <div id="tab-config" class="tab-panel">
    {config_html}
  </div>

<script>
/* Actualización en vivo por SSE (Server-Sent Events).
   El servidor deja una conexión abierta y manda solo los pedazos que
   cambiaron. Antes la página entera se recargaba cada 5 segundos, y eso
   reseteaba el scroll, cerraba los detalles abiertos y borraba lo que
   estuvieras escribiendo en el buscador. */
(function() {{
  var estado = document.getElementById('estado-vivo');
  if (!window.EventSource) {{ volverAlRefresco('tu navegador no soporta eventos'); return; }}

  function volverAlRefresco(motivo) {{
    if (estado) {{ estado.textContent = 'se actualiza cada 5 segundos'; }}
    setTimeout(function() {{ location.reload(); }}, 5000);
  }}

  function pintar(id, html) {{
    var nodo = document.getElementById(id);
    /* Solo se toca el DOM si el contenido cambió: si no, se perderían los
       detalles que el usuario tenga desplegados. */
    if (nodo && nodo.innerHTML !== html) {{ nodo.innerHTML = html; }}
  }}

  var filtro = '';
  var campo = document.querySelector('input[name="q"]');
  if (campo && campo.value) {{ filtro = '?q=' + encodeURIComponent(campo.value); }}

  var fuente = new EventSource('/eventos' + filtro);
  /* Se expone para poder cerrarlo a mano al apagar el proxy: ver
     confirmarApagado(). */
  window.fuenteDeEventos = fuente;
  var fallas = 0;

  fuente.onmessage = function(evento) {{
    fallas = 0;
    if (estado) {{ estado.textContent = 'en vivo'; }}
    var datos = JSON.parse(evento.data);
    pintar('tarjetas', datos.tarjetas);
    pintar('ruido', datos.ruido);
    pintar('salud', datos.salud);
    pintar('historial', datos.historial);
    pintar('estadisticas', datos.estadisticas);
  }};

  fuente.onerror = function() {{
    /* EventSource reconecta solo. Recién si insiste en fallar -por ejemplo
       porque el proxy se apagó o no hay lugar para más pestañas- se vuelve
       al refresco clásico, para no quedar con una página congelada. */
    if (estado) {{ estado.textContent = 'reconectando...'; }}
    fallas += 1;
    if (fallas >= 3) {{ fuente.close(); volverAlRefresco('sin conexión de eventos'); }}
  }};
}})();

var SALTO = String.fromCharCode(10);   /* salto de línea, sin escapes que se
                                          pierdan al generar la página */
/* Un solo botón para exportar: se pregunta el formato y se respeta el filtro
   del buscador que esté puesto, para que lo exportado sea lo que se ve. */
function exportar() {{
  var enCSV = confirm('¿En qué formato querés exportar el historial?' + SALTO + SALTO +
                      'Aceptar = CSV (se abre con Excel)' + SALTO +
                      'Cancelar = JSON (para procesarlo con otra herramienta)');
  var filtro = '';
  var campo = document.querySelector('input[name="q"]');
  if (campo && campo.value) {{ filtro = '?q=' + encodeURIComponent(campo.value); }}
  window.location = (enCSV ? '/export.csv' : '/export.json') + filtro;
}}
/* Confirmaciones que mencionan un dominio.

   El dominio NO se interpola dentro del atributo, y esa es toda la gracia.
   Antes se armaba onclick="return confirm('... ' + 'DOMINIO' + ' ...')" con
   el dominio escapado como HTML, y eso NO alcanza: el navegador decodifica
   las entidades del atributo ANTES de pasarle el texto al parser de
   JavaScript, así que un &#x27; vuelve a ser una comilla y cierra el string.
   Un host con comillas -que un dominio real no puede tener, pero un proceso
   local sí puede pedir por CONNECT- terminaba ejecutando JavaScript en el
   panel al hacer clic en "Permitir".

   Ahora el dominio viaja en data-dominio, que es contexto de atributo y ahí
   el escape de HTML sí es suficiente, y se lee con getAttribute, que
   devuelve texto sin evaluarlo nunca. */
var TEXTOS_CONFIRMACION = {{
  'quitar': '¿Quitar DOMINIO?',
  'permitir': '¿Permitir siempre DOMINIO?',
  'permitir-siempre': '¿Permitir siempre DOMINIO? Gana por sobre blocklist, TOR y AbuseIPDB.',
  'bloquear': '¿Bloquear siempre DOMINIO?',
  'ocultar': '¿Ocultar DOMINIO del panel? Se sigue registrando y filtrando igual: solo deja de aparecer en el historial y en las estadísticas.'
}};
function confirmarAccion(el, clave) {{
  var dominio = el.getAttribute('data-dominio') || '';
  var texto = TEXTOS_CONFIRMACION[clave] || '¿Seguro?';
  return confirm(texto.split('DOMINIO').join(dominio));
}}
/* Apagar tiene su propia confirmación, y no una del estilo "¿seguro?", porque
   la consecuencia no es obvia: el proxy deja de filtrar, pero el navegador
   sigue configurado para pasar por él, así que lo que se nota primero es que
   no anda internet. Mejor decirlo antes que después. */
function confirmarApagado() {{
  if (!confirm('¿Apagar SecureProxy?' + SALTO + SALTO +
               'Se corta el proceso entero: deja de filtrar y el panel se ' +
               'cierra. Si tenés el proxy configurado en el navegador o en el ' +
               'sistema, vas a quedarte sin navegar hasta que lo saques o lo ' +
               'vuelvas a levantar.')) {{
    return false;
  }}
  /* El refresco en vivo tiene que parar acá: si sigue intentando reconectarse
     mientras el proceso muere, la página de despedida arranca mostrando un
     cartel de "sin conexión" que hace pensar que algo falló. */
  if (window.fuenteDeEventos) {{ try {{ window.fuenteDeEventos.close(); }} catch (e) {{}} }}
  return true;
}}
/* Despliega la fila de detalle que ya viene en la página, sin ir al servidor.
   Funciona como acordeón: abrir uno cierra el que estuviera abierto. Con dos
   detalles abiertos a la vez la tabla se estira y hay que scrollear para
   comparar, que es justo lo contrario de lo que uno quiere al mirar dos
   conexiones parecidas. */
function verDetalle(id) {{
  var fila = document.getElementById(id);
  if (!fila) {{ return; }}
  var yaEstaba = fila.classList.contains('abierta');
  document.querySelectorAll('.detalle-fila.abierta').forEach(function(el) {{
    el.classList.remove('abierta');
  }});
  if (!yaEstaba) {{ fila.classList.add('abierta'); }}
}}
var TAB_STORAGE_KEY = 'secureproxy_dashboard_tab';
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(function(el) {{ el.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(el) {{ el.classList.remove('active'); }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  try {{ localStorage.setItem(TAB_STORAGE_KEY, name); }} catch (e) {{ /* sin soporte de localStorage: no pasa nada */ }}
}}
(function() {{
  function abrir(nombre) {{
    var btn = document.querySelector('.tab-btn[data-tab="' + nombre + '"]');
    if (btn) {{ showTab(nombre, btn); return true; }}
    return false;
  }}
  /* Si la URL trae una consulta OSINT, es porque se hizo clic en "Investigar":
     se abre directamente la pestaña Consultar, con el dominio ya cargado y la
     consulta ya resuelta del lado del servidor. Antes el clic solo te subía al
     principio de la página y no se veía nada. */
  if (/[?&]osint=/.test(window.location.search)) {{
    abrir('osint');
    var panel = document.getElementById('tab-osint');
    if (panel) {{ panel.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}
    return;
  }}
  // Si no, se restaura la pestaña que se estaba mirando antes del refresco,
  // en vez de volver siempre a "Historial".
  var saved = null;
  try {{ saved = localStorage.getItem(TAB_STORAGE_KEY); }} catch (e) {{ /* nada */ }}
  if (saved) {{ abrir(saved); }}
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
        destino = self._ip_de_destino(decision, host, permitir_resolver=False)
        geo = self._geo(destino)
        self.logger_db.log_request(
            self.client_address[0], method, host, port, "-", True,
            reason=decision.reason, duration_ms=duration_ms,
            dest_ip=destino, country=geo["pais"],
            asn=geo["asn"], provider=geo["proveedor"],
            noisy=self._es_ruido(host), process=self._proceso(),
        )
        self.notifier.send_alert(f"🚫 SecureProxy bloqueó una conexión a {host}\nMotivo: {decision.reason}")
        # Aviso en el escritorio. Va después de registrar y de notificar, y
        # nunca espera: encola y sigue. Lanzar una notificación tarda cientos
        # de milisegundos y eso no puede estar en el camino de una conexión.
        alertas = getattr(self, "alertas", None)
        if alertas is not None:
            try:
                alertas.avisar_bloqueo(host, decision.reason, self._proceso())
            except Exception:
                pass
        if decision.resolved_ip:
            self.firewall.block_ip(decision.resolved_ip)


class DashboardOnlyRequestHandler(ProxyRequestHandler):
    """Sirve SOLO el dashboard, en un puerto propio.

    Por qué existe: antes el dashboard se servía en el MISMO puerto que el
    proxy (8888). Eso mezcla dos protocolos muy distintos en un socket -el
    proxy maneja CONNECT, túneles y conexiones de larga vida- y el navegador
    termina reusando conexiones del pool que el proxy ya cerró, dejando la
    página cargando para siempre al reabrirla.

    Con el dashboard en su propio puerto (8889 por defecto) desaparece esa
    clase de problema, y queda igual que SecureDNS: el servicio por un lado,
    el panel web por otro. El path raíz "/" muestra el dashboard, así la
    dirección es simplemente http://127.0.0.1:8889/
    """

    def do_GET(self) -> None:  # noqa: N802
        parsed_path = urlsplit(self.path)
        clean_path = parsed_path.path.rstrip("/")
        rutas = {
            "": self._serve_dashboard,            # http://127.0.0.1:8889/
            "/dashboard": self._serve_dashboard,  # compatibilidad con el link viejo
            "/allow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=True),
            "/unallow": lambda: self._handle_list_edit(self.filter_engine.allowlist, parsed_path.query, add=False),
            "/blockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=True),
            "/unblockdomain": lambda: self._handle_list_edit(self.filter_engine.blocklist, parsed_path.query, add=False),
            "/clear-cache": self._handle_clear_cache,
            "/config": lambda: self._handle_config_change(parsed_path.query),
            "/osint": self._serve_dashboard,
            "/export.csv": lambda: self._exportar(parsed_path.query, "csv"),
            "/export.json": lambda: self._exportar(parsed_path.query, "json"),
            "/sincronizar": self._sincronizar_feeds,
            "/nivel": lambda: self._aplicar_nivel(
                (parse_qs(parsed_path.query).get("v") or [""])[0]
            ),
            "/ocultar": lambda: self._handle_ruido(parsed_path.query, add=True),
            "/mostrar": lambda: self._handle_ruido(parsed_path.query, add=False),
            "/eventos": lambda: self._serve_eventos(parsed_path.query),
            "/health": self._serve_health,
            # Solo vive en el puerto del panel. En el puerto del proxy pasa
            # tráfico de terceros: por poco probable que sea que alguien
            # acierte, no se gana nada teniendo el apagado ahí también.
            "/apagar": self._handle_apagar,
        }
        handler = rutas.get(clean_path)
        if handler is None:
            self.send_error(404, "En este puerto solo vive el dashboard")
            return
        # /health queda afuera del chequeo: lo consulta SecureCenter para
        # saber si el proxy está vivo, no cambia nada y no expone datos.
        if clean_path != "/health" and not self._accion_autorizada(clean_path):
            self._rechazar_por_origen()
            return
        handler()

    def _serve_health(self) -> None:
        """Chequeo liviano para paneles y orquestadores."""
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _reject(self) -> None:
        """Este puerto no proxea nada: es solo el panel."""
        self.send_error(405, "Este puerto es solo el dashboard; el proxy escucha aparte")

    def do_POST(self) -> None:  # noqa: N802
        self._reject()

    def do_PUT(self) -> None:  # noqa: N802
        self._reject()

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._reject()


class ThreadingProxyServer(ThreadingHTTPServer):
    # ThreadingHTTPServer ya combina ThreadingMixIn + HTTPServer.
    daemon_threads = True
    allow_reuse_address = True

    # Techo de conexiones atendidas a la vez. Existía como opción en el
    # config.yaml y en el README ("cuántas conexiones atiende en paralelo"),
    # pero no se leía en ningún lado: era un hilo nuevo por conexión, sin
    # límite. Medido: 250 túneles simultáneos dejaban el proceso con 254
    # hilos y 581 descriptores, sin rechazar ninguno. Peor que el agujero de
    # disponibilidad era que la documentación mentía, y alguien podía bajar
    # ese número creyendo que se estaba protegiendo.
    max_threads = 0  # 0 = sin límite
    _conexiones_activas = 0
    _cupo_lock = threading.Lock()

    def process_request(self, request, client_address) -> None:
        if self.max_threads > 0:
            with self._cupo_lock:
                if self._conexiones_activas >= self.max_threads:
                    # Se rechaza cerrando: el cliente lo ve como una conexión
                    # rehusada y reintenta, que es mejor que aceptarla y
                    # dejarla esperando un hilo que no hay.
                    self.shutdown_request(request)
                    return
                self._conexiones_activas += 1
        super().process_request(request, client_address)

    def shutdown_request(self, request) -> None:
        super().shutdown_request(request)

    def close_request(self, request) -> None:
        if self.max_threads > 0:
            with self._cupo_lock:
                self._conexiones_activas = max(0, self._conexiones_activas - 1)
        super().close_request(request)

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
    geoip=None,
    vista=None,
    procesos=None,
    alertas=None,
    max_threads: int = 0,
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
            "geoip": geoip,
            "vista": vista,
            "procesos": procesos,
            "alertas": alertas,
        },
    )
    servidor = ThreadingProxyServer((host, port), handler_class)
    servidor.max_threads = max(0, int(max_threads or 0))
    return servidor


def build_dashboard_server(
    host: str,
    port: int,
    filter_engine: FilterEngine,
    logger_db: LoggerDB,
    notifier: TelegramNotifier,
    firewall: FirewallManager,
    allowlist: Allowlist,
    geoip=None,
    vista=None,
    alertas=None,
    apagar=None,
) -> ThreadingProxyServer:
    """Servidor del dashboard, en su propio puerto y separado del proxy.

    Comparte el estado (mismo filter_engine, mismos logs), pero no atiende
    tráfico proxeado: así el panel web nunca compite con el proxy por el
    mismo socket ni queda a merced de conexiones reusadas."""
    handler_class = type(
        "InjectedDashboardRequestHandler",
        (DashboardOnlyRequestHandler,),
        {
            "filter_engine": filter_engine,
            "logger_db": logger_db,
            "notifier": notifier,
            "firewall": firewall,
            "allowlist": allowlist,
            "geoip": geoip,
            "vista": vista,
            "alertas": alertas,
            # Se guarda envuelto en staticmethod porque si `apagar` es una
            # función suelta, dejarla como atributo de clase la convierte en
            # método y el primer argumento pasa a ser el handler.
            "apagar": staticmethod(apagar) if callable(apagar) else None,
        },
    )
    return ThreadingProxyServer((host, port), handler_class)
