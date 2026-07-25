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
    """Cliente con cache en memoria para la API de AbuseIPDB."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, cache_ttl: int = 3600):
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[int, float]] = {}  # ip -> (score, ts)

    def get_abuse_score(self, ip: str) -> int:
        """Devuelve el abuseConfidenceScore (0-100) para una IP. 0 si no hay API key
        configurada o si la consulta falla (fail-open a nivel de reputación, no de red)."""
        if not self.api_key:
            return 0

        cached = self._cache.get(ip)
        if cached and (time.time() - cached[1]) < self.cache_ttl:
            return cached[0]

        try:
            response = requests.get(
                self.API_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            response.raise_for_status()
            score = response.json()["data"]["abuseConfidenceScore"]
        except (requests.RequestException, KeyError, ValueError):
            score = 0

        self._cache[ip] = (score, time.time())
        return score


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
