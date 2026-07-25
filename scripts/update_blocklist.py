#!/usr/bin/env python3
"""Descarga feeds públicos de amenazas (URLhaus, OpenPhish y Feodo Tracker) y
genera data/blocklist_feeds.txt (dominios) y data/ip_blocklist_feeds.txt (IPs).

Estos archivos se combinan automáticamente con data/blocklist.txt (lista
manual de dominios) cuando corre el proxy - no hace falta tocar nada más.

Se puede correr manualmente (opción 4 del menú `SecureProxy.bat`, que siempre
fuerza la descarga), o dejar que `scripts/run_proxy.py` lo haga solo al
arrancar, respetando un intervalo mínimo entre actualizaciones para no
descargar de más (ver `filtering.feeds_update_interval_hours` en
config/config.yaml).

Fuentes:
- URLhaus (abuse.ch): dominios que reparten malware activamente.
- OpenPhish: dominios usados en campañas de phishing activas.
- Feodo Tracker (abuse.ch): IPs de servidores de comando-y-control (C2) de
  botnets conocidas (Dridex, Emotet, TrickBot, QakBot, etc).
"""

import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
FEODOTRACKER_FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

DOMAIN_OUTPUT_PATH = PROJECT_ROOT / "data" / "blocklist_feeds.txt"
IP_OUTPUT_PATH = PROJECT_ROOT / "data" / "ip_blocklist_feeds.txt"


def fetch_urlhaus_domains() -> set[str]:
    """URLhaus publica un 'hostfile' en formato `0.0.0.0 dominio.com` - ya viene
    listo para usar como blocklist, solo hay que quedarse con la segunda columna."""
    domains: set[str] = set()
    try:
        response = requests.get(URLHAUS_HOSTFILE, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                domains.add(parts[1].lower())
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar URLhaus: {exc}")
    return domains


def fetch_openphish_domains() -> set[str]:
    """OpenPhish publica URLs completas de phishing; extraemos solo el dominio
    de cada una (bloqueamos el dominio entero, no la URL puntual)."""
    domains: set[str] = set()
    try:
        response = requests.get(OPENPHISH_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            hostname = urlsplit(line).hostname
            if hostname:
                domains.add(hostname.lower())
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar OpenPhish: {exc}")
    return domains


def fetch_feodotracker_ips() -> set[str]:
    """Feodo Tracker publica una lista de texto con una IP de C2 por línea
    (con comentarios que empiezan con #)."""
    ips: set[str] = set()
    try:
        response = requests.get(FEODOTRACKER_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar Feodo Tracker: {exc}")
    return ips


def is_stale(path: Path, min_interval_hours: float) -> bool:
    """True si el archivo no existe, o si pasó más tiempo que min_interval_hours
    desde la última vez que se generó."""
    if not path.exists():
        return True
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    return age_hours >= min_interval_hours


def _write_list(path: Path, items: set[str], source_note: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Generado automáticamente por scripts/update_blocklist.py\n")
        f.write(f"# Fuentes: {source_note}. NO editar a mano: se sobreescribe.\n")
        f.write(f"# Total de entradas: {len(items)}\n\n")
        for item in sorted(items):
            f.write(item + "\n")


def main(force: bool = False, min_interval_hours: float = 6) -> bool:
    """Descarga y regenera las listas. Devuelve True si efectivamente se
    actualizó algo, False si se omitió (por frescura) o falló todo."""

    if not force and not is_stale(DOMAIN_OUTPUT_PATH, min_interval_hours):
        print(
            f"[update_blocklist] Las listas se actualizaron hace menos de "
            f"{min_interval_hours}h, se omite la descarga."
        )
        return False

    print("[update_blocklist] Descargando feeds de amenazas (URLhaus + OpenPhish + Feodo Tracker)...")
    domains = fetch_urlhaus_domains() | fetch_openphish_domains()
    ips = fetch_feodotracker_ips()

    if not domains and not ips:
        print(
            "[update_blocklist] No se obtuvo ningún dato (¿sin internet? "
            "¿los feeds están caídos?). No se modifican los archivos anteriores."
        )
        return False

    if domains:
        _write_list(DOMAIN_OUTPUT_PATH, domains, "URLhaus (abuse.ch) + OpenPhish")
        print(f"[update_blocklist] {len(domains)} dominios guardados en {DOMAIN_OUTPUT_PATH}")

    if ips:
        _write_list(IP_OUTPUT_PATH, ips, "Feodo Tracker (abuse.ch)")
        print(f"[update_blocklist] {len(ips)} IPs de C2 guardadas en {IP_OUTPUT_PATH}")

    return True


if __name__ == "__main__":
    # Corrido manualmente (o desde el menú): siempre fuerza la descarga.
    updated = main(force=True)
    if updated:
        print("[update_blocklist] Si el proxy ya estaba corriendo, se recarga solo (no hace falta reiniciar).")
