"""Fuentes de inteligencia de amenazas: blocklist local, AbuseIPDB y nodos TOR."""

import socket
import time
from pathlib import Path

import requests


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
        target_path.write_text(
            "\n".join(kept) + ("\n" if kept else ""), encoding="utf-8"
        )
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

    @property
    def circuit_open(self) -> bool:
        """True si el circuito está abierto (dejando pasar solo consultas
        de prueba cada RESET_TIMEOUT_SECONDS) en este momento."""
        if self._circuit_opened_at is None:
            return False
        return (time.time() - self._circuit_opened_at) < self.RESET_TIMEOUT_SECONDS

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_opened_at = None

    def _record_failure(self) -> None:
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

        try:
            response = requests.get(
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
    """Mantiene en memoria la lista de IPs de salida de la red TOR."""

    SOURCE_URL = "https://check.torproject.org/torbulkexitlist"

    def __init__(self, cache_ttl: int = 21600):
        self.cache_ttl = cache_ttl
        self._nodes: set[str] = set()
        self._last_fetch = 0.0

    def _refresh_if_needed(self) -> None:
        if (time.time() - self._last_fetch) < self.cache_ttl and self._nodes:
            return
        try:
            response = requests.get(self.SOURCE_URL, timeout=5)
            response.raise_for_status()
            self._nodes = {line.strip() for line in response.text.splitlines() if line.strip()}
            self._last_fetch = time.time()
        except requests.RequestException:
            # Si falla la descarga, seguimos con lo que ya teníamos en memoria
            # (puede ser un set vacío la primera vez, y no bloqueamos por eso).
            pass

    def is_tor_exit_node(self, ip: str) -> bool:
        self._refresh_if_needed()
        return ip in self._nodes


def resolve_host_to_ip(host: str) -> str | None:
    """Resuelve un hostname a su IP. Devuelve None si falla la resolución."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
