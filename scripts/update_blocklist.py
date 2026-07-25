#!/usr/bin/env python3
"""Descarga feeds públicos de amenazas (URLhaus + OpenPhish) y genera
data/blocklist_feeds.txt con los dominios encontrados.

Este archivo se combina automáticamente con data/blocklist.txt (tu lista
manual) cuando corre el proxy — no hace falta tocar nada más.

Se puede correr manualmente cuando quieras ("Actualizar listas de amenazas"
en el menú), o programarlo para que se ejecute solo cada tanto.

Fuentes:
- URLhaus (abuse.ch): dominios que reparten malware activamente.
- OpenPhish: dominios usados en campañas de phishing.
"""

import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
OUTPUT_PATH = PROJECT_ROOT / "data" / "blocklist_feeds.txt"


def fetch_urlhaus_domains() -> set[str]:
    """URLhaus publica un 'hostfile' en formato `0.0.0.0 dominio.com` — ya viene
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


def main() -> None:
    print("[update_blocklist] Descargando feeds de amenazas (URLhaus + OpenPhish)...")
    domains = fetch_urlhaus_domains() | fetch_openphish_domains()

    if not domains:
        print(
            "[update_blocklist] No se obtuvo ningún dominio (¿sin internet? "
            "¿los feeds están caídos?). No se modifica el archivo anterior."
        )
        return

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("# Generado automáticamente por scripts/update_blocklist.py\n")
        f.write("# Fuentes: URLhaus (abuse.ch) + OpenPhish. NO editar a mano: se sobreescribe\n")
        f.write("# cada vez que se corre este script.\n")
        f.write(f"# Total de dominios: {len(domains)}\n\n")
        for domain in sorted(domains):
            f.write(domain + "\n")

    print(f"[update_blocklist] Listo: {len(domains)} dominios guardados en {OUTPUT_PATH}")
    print("[update_blocklist] Si el proxy ya estaba corriendo, reiniciealo para que tome la lista nueva.")


if __name__ == "__main__":
    main()
