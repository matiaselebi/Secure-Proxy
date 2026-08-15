"""Fuentes de inteligencia de amenazas: blocklist local, AbuseIPDB y nodos TOR."""

import os
import socket
import tempfile
import threading
import time
from pathlib import Path


def escribir_atomico(path: Path, contenido: str) -> None:
    """Escribe el archivo entero de una, o no lo escribe.

    `write_text` trunca primero y escribe después, así que hay una ventana
    -de decenas de milisegundos para un archivo de megabytes- en la que otro
    hilo que recargue la lista la lee vacía o a la mitad. Y como la recarga
    corre cada 15 segundos, esa ventana significa conexiones que deberían
    bloquearse y pasan. Peor todavía: si el proceso muere justo ahí, la
    lista queda truncada para siempre.

    Escribir a un temporal y renombrar arregla las dos cosas: `os.replace`
    es atómico, así que un lector ve el archivo viejo o el nuevo, nunca uno
    a medio hacer.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contenido)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporal, path)
    except BaseException:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise

import requests

from . import http_client, intel_puente


class Blocklist:
    """Lista negra de dominios, cargada desde uno o varios archivos de texto.

    Se admite más de un archivo para poder combinar una lista curada a mano
    (ej. data/blocklist.txt) con una lista generada automáticamente desde
    feeds de amenazas como URLhaus/OpenPhish (ej. data/blocklist_feeds.txt),
    sin que se pisen entre sí.
    """

    def __init__(self, path: str | list[str]):
        if isinstance(path, str):
            path = [path]
        self.paths = [Path(p) for p in path]
        self._domains: set[str] = set()
        self.reload()

    def reload(self) -> None:
        domains = set()
        for path in self.paths:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            domains.add(line)
        self._domains = domains

    def is_blocked(self, domain: str) -> bool:
        domain = domain.lower()
        if domain in self._domains:
            return True
        # Bloquea también subdominios: sub.malicious-example.com -> malicious-example.com
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._domains:
                return True
        return False

    def add_and_reload(self, domain: str) -> None:
        """Agrega un dominio al primer archivo (el manual, paths[0]) y
        recarga en caliente. Pensado para el botón "Permitir"/"Bloquear" del
        dashboard, y para la opción equivalente del menú .bat."""
        domain = domain.strip().lower()
        if not domain:
            return
        target_path = self.paths[0]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if domain not in self.manual_entries():
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(domain + "\n")
        self.reload()

    def remove_and_reload(self, domain: str) -> None:
        """Saca un dominio del primer archivo (el manual, paths[0]) y
        recarga en caliente. Solo afecta la lista manual: si el mismo
        dominio también está en un archivo generado por feeds automáticos
        (paths[1] en adelante), ese no se toca acá."""
        domain = domain.strip().lower()
        target_path = self.paths[0]
        if not target_path.exists():
            return
        lines = target_path.read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if line.strip().lower() != domain]
        escribir_atomico(target_path, "\n".join(kept) + ("\n" if kept else ""))
        self.reload()

    def manual_entries(self) -> list[str]:
        """Dominios definidos a mano en el primer archivo (paths[0]), sin
        contar comentarios ni lo que viene de feeds automáticos. Pensado
        para mostrarlos en el dashboard."""
        target_path = self.paths[0]
        if not target_path.exists():
            return []
        entries = set()
        for line in target_path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                entries.add(line)
        return sorted(entries)

    def dominios(self) -> set[str]:
        """Todos los dominios cargados, de todos los archivos. A diferencia
        de `manual_entries()`, incluye los que vienen de feeds automáticos.
        Lo usa el filtro de ruido del panel, que necesita la lista entera
        para armar la consulta de exclusión."""
        return set(self._domains)

    def normalizar_archivo(self) -> int:
        """Limpia la lista MANUAL (paths[0]) dejando cada entrada como un
        dominio a secas. Devuelve cuántas líneas cambiaron.

        Se corre al arrancar, para las listas que se armaron antes de que la
        limpieza existiera: una entrada como "https://www.ejemplo.com/algo"
        no matcheaba nunca -el proxy compara contra el host, que es
        "www.ejemplo.com"- así que era una regla que parecía puesta y no
        hacía nada. Peor que no tenerla.

        Los comentarios y el orden se respetan; solo se tocan las líneas que
        efectivamente cambian, y se sacan los duplicados que aparezcan
        después de normalizar.
        """
        from .validation import normalizar_dominio

        target_path = self.paths[0]
        if not target_path.exists():
            return 0

        cambios = 0
        vistos: set[str] = set()
        salida: list[str] = []
        for linea in target_path.read_text(encoding="utf-8").splitlines():
            crudo = linea.strip()
            if not crudo or crudo.startswith("#"):
                salida.append(linea)
                continue
            limpio, _avisos = normalizar_dominio(crudo)
            if not limpio:
                cambios += 1
                continue
            if limpio in vistos:
                cambios += 1  # duplicado que aparece recién al normalizar
                continue
            vistos.add(limpio)
            if limpio != crudo:
                cambios += 1
            salida.append(limpio)

        if cambios:
            escribir_atomico(target_path, "\n".join(salida) + ("\n" if salida else ""))
            self.reload()
        return cambios


class Allowlist(Blocklist):
    """Lista blanca de dominios: gana por sobre CUALQUIER otro chequeo
    (blocklist, TOR, AbuseIPDB, IPBlocklist). Reutiliza toda la lógica de
    coincidencia y edición de Blocklist (dominio exacto + subdominios, alta,
    baja y listado), solo cambia el nombre del método de consulta para que
    se lea claro en el motor de filtrado."""

    def is_allowed(self, domain: str) -> bool:
        return self.is_blocked(domain)


class IPBlocklist:
    """Lista negra de IPs, cargada desde uno o varios archivos de texto
    (ej. data/ip_blocklist_feeds.txt, generado por update_blocklist.py con
    la lista de IPs de C2 de Feodo Tracker). Coincidencia exacta, sin rangos."""

    def __init__(self, path: str | list[str]):
        if isinstance(path, str):
            path = [path]
        self.paths = [Path(p) for p in path]
        self._ips: set[str] = set()
        self.reload()

    def reload(self) -> None:
        ips = set()
        for path in self.paths:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ips.add(line)
        self._ips = ips

    def is_blocked(self, ip: str) -> bool:
        return ip in self._ips


class AbuseIPDBClient:
    """Cliente con cache en memoria (y opcionalmente persistente en disco)
    para la API de AbuseIPDB.

    Incluye un circuit breaker simple: si la API falla varias veces
    seguidas (caída, rate-limit, etc.), en vez de seguir intentando y
    pagando el timeout completo (5s) en cada request que pasa por el
    proxy, el cliente "abre el circuito" y devuelve 0 (fail-open) de
    inmediato durante un tiempo de enfriamiento, sin siquiera intentar la
    llamada de red. Pasado ese tiempo, deja pasar UNA consulta de prueba;
    si funciona, cierra el circuito y vuelve a la normalidad."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    # Cuántos fallos consecutivos abren el circuito.
    FAILURE_THRESHOLD = 3
    # Cuánto tiempo (segundos) se mantiene abierto antes de probar de nuevo.
    RESET_TIMEOUT_SECONDS = 60

    def __init__(self, api_key: str, cache_ttl: int = 3600, persistent_cache=None):
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.persistent_cache = persistent_cache  # PersistentIPCache | None
        self._cache: dict[str, tuple[int, float]] = {}  # ip -> (score, ts)
        self._consecutive_failures = 0
        self._circuit_opened_at: float | None = None
        # Última consulta que respondió bien. Es lo que el panel de salud
        # muestra como "última sincronización" de esta fuente.
        self._last_ok: float = 0.0
        # Protege el contador del circuit breaker y el cache. Sin esto, dos
        # cosas: el `+= 1` de los fallos es read-modify-write y se perdían
        # incrementos, así que el circuito abría tarde; y N conexiones
        # simultáneas hacia una IP nueva disparaban N consultas idénticas a
        # la API, quemando el cupo gratuito (1000 por día) de a varias por
        # vez. TorExitNodeList ya tenía un lock por este mismo motivo.
        self._lock = threading.Lock()
        # IPs que se están consultando ahora mismo, para no pedir la misma
        # dos veces en paralelo.
        self._en_curso: set[str] = set()

    @property
    def circuit_open(self) -> bool:
        """True si el circuito está abierto (dejando pasar solo consultas
        de prueba cada RESET_TIMEOUT_SECONDS) en este momento."""
        if self._circuit_opened_at is None:
            return False
        return (time.time() - self._circuit_opened_at) < self.RESET_TIMEOUT_SECONDS

    def _record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._circuit_opened_at = None
            self._last_ok = time.time()

    def estado(self) -> dict:
        """Para el panel de salud. Distingue tres situaciones que se ven
        parecidas pero no lo son: sin API key configurada, circuito abierto
        porque la API viene fallando, y funcionando."""
        if not self.api_key:
            return {
                "ok": False,
                "motivo": "sin API key",
                "ultimo_ok": 0.0,
                # La ayuda va acá y no en el panel porque quien conoce el
                # motivo exacto es quien lo detecta: sin esto, el usuario ve
                # "sin API key" y tiene que adivinar dónde se pone.
                "ayuda": "poné ABUSEIPDB_API_KEY en el archivo .env y reiniciá el proxy",
            }
        if self.circuit_open:
            return {
                "ok": False,
                "motivo": f"circuito abierto ({self._consecutive_failures} fallos seguidos)",
                "ultimo_ok": self._last_ok,
            }
        return {"ok": True, "motivo": "", "ultimo_ok": self._last_ok}

    def _record_failure(self) -> None:
        # Bajo lock porque `+= 1` es leer, sumar y escribir: con varias
        # conexiones fallando a la vez se perdían incrementos y el circuito
        # abría más tarde de lo que debía.
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.FAILURE_THRESHOLD:
                self._circuit_opened_at = time.time()

    def get_abuse_score(self, ip: str) -> int:
        """Devuelve el abuseConfidenceScore (0-100) para una IP. 0 si no hay API key
        configurada, si el circuito está abierto, o si la consulta falla
        (fail-open a nivel de reputación, no de red: un problema con
        AbuseIPDB no debe tumbar el proxy ni bloquear tráfico legítimo)."""
        if not self.api_key:
            return 0

        cached = self._cache.get(ip)
        if cached and (time.time() - cached[1]) < self.cache_ttl:
            return cached[0]

        # Cache en memoria: no la tenemos (recién reiniciamos, por ejemplo).
        # Antes de gastar cupo de la API, nos fijamos si ya la consultamos en
        # una corrida anterior y quedó guardada en disco.
        if self.persistent_cache is not None:
            persisted_score = self.persistent_cache.get(ip, self.cache_ttl)
            if persisted_score is not None:
                self._cache[ip] = (persisted_score, time.time())
                return persisted_score

        if self.circuit_open:
            # No perdemos 5 segundos de timeout por request si ya sabemos
            # que la API viene fallando: cortamos acá mismo.
            return 0

        with self._lock:
            if ip in self._en_curso:
                # Otro hilo ya está preguntando por esta misma IP. Devolver 0
                # es lo mismo que hace el resto de esta función cuando no
                # sabe: fail-open a nivel de reputación. Mejor eso que
                # duplicar la consulta y quemar cupo.
                return 0
            self._en_curso.add(ip)

        try:
            # http_client, no requests: la consulta a la API no puede salir
            # por el proxy del sistema, que es este mismo proxy.
            response = http_client.get(
                self.API_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            response.raise_for_status()
            score = response.json()["data"]["abuseConfidenceScore"]
            self._record_success()
        except (requests.RequestException, KeyError, ValueError):
            score = 0
            self._record_failure()
        finally:
            with self._lock:
                self._en_curso.discard(ip)

        self._cache[ip] = (score, time.time())
        if self.persistent_cache is not None:
            self.persistent_cache.set(ip, score)
        return score

    def clear_cache(self) -> None:
        """Borra el cache en memoria y, si hay uno configurado, también el
        persistente. Pensado para el botón "Borrar cache" del dashboard.
        No afecta el estado del circuit breaker."""
        self._cache.clear()
        if self.persistent_cache is not None:
            self.persistent_cache.clear()


class TorExitNodeList:
    """¿Una IP es un nodo de salida de TOR? Lo contesta Secure-Intel.

    ESTA CLASE YA NO DESCARGA NADA, y esa es la parte importante.

    Antes bajaba la lista de check.torproject.org por su cuenta, y esa
    descarga tuvo el peor bug que tuvo este proyecto: si fallaba, la lista
    quedaba vacía, y la condición de "¿hace falta refrescar?" daba verdadero
    SIEMPRE. Como esto se consulta en CADA conexión que evalúa el proxy, cada
    conexión disparaba una descarga nueva. En la PC donde apareció, eso
    terminó en 1.644.074 pedidos a check.torproject.org en dos días.

    Se arregló en su momento con un fusible de reintentos. Ahora directamente
    no hace falta: la lista la mantiene Secure-Intel, que la baja una vez cada
    seis horas pase lo que pase, valida que no haya encogido y avisa si está
    congelada. Es la fase 2 del punto 8.

    LO QUE NO SE SABE SE DICE

    Si Secure-Intel no está, `is_tor_exit_node` devuelve False y `estado()`
    dice que no hay lista. No se inventa un "no es TOR" con cara de
    certeza: esa es exactamente la forma de apagar una detección sin que
    nadie se entere.
    """

    def __init__(self, cache_ttl: int = 21600):
        # `cache_ttl` se conserva en la firma porque lo pasa `run_proxy.py` y
        # el config. Ya no hace nada: quien decide cada cuánto refrescar es
        # Secure-Intel, que lleva la cuenta por fuente.
        self.cache_ttl = cache_ttl
        self._consultas = 0
        self._sin_datos = 0

    def is_tor_exit_node(self, ip: str) -> bool:
        self._consultas += 1
        resultado = intel_puente.es_tor(ip)
        if resultado is None:
            # No se pudo saber. Se cuenta para poder decirlo en el panel, y se
            # contesta False: no bloquear por falta de datos es lo correcto,
            # siempre que quede dicho que faltan.
            self._sin_datos += 1
            return False
        return resultado

    def estado(self) -> dict:
        """Para el panel de salud. Dice la verdad incluso cuando es fea."""
        hay = intel_puente.disponible()
        return {
            "fuente": "Secure-Intel",
            "disponible": hay,
            "consultas": self._consultas,
            "sin_datos": self._sin_datos,
            "detalle": ("la lista de TOR la mantiene Secure-Intel" if hay else
                        "no está Secure-Intel: no puedo saber si una IP es de TOR"),
        }


def resolve_host_to_ip(host: str) -> str | None:
    """Resuelve un hostname a su IP. Devuelve None si falla la resolución.

    Se atrapa también `UnicodeError`, que NO es un `gaierror`: lo levanta el
    codec IDNA cuando una etiqueta del nombre pasa los 63 caracteres o trae
    bytes raros. Antes esa excepción salía del motor de filtrado sin que
    nadie la atrapara y mataba el hilo de la conexión, dejando al cliente sin
    respuesta y sin registrar nada. Y la ironía es que los nombres con
    etiquetas larguísimas son justo el patrón de los dominios generados por
    algoritmo y del tunneling por DNS: el caso que más querés ver era el que
    rompía el proxy.
    """
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        return None
