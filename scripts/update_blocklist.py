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

import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Las descargas usan http_client y no `requests` directo: si salieran por el
# proxy del sistema -que es SecureProxy- el proxy estaria bajando sus
# propias listas a traves de si mismo (ver http_client.py).
from secureproxy import feeds_status, http_client  # noqa: E402

DATA_DIR = PROJECT_ROOT / "data"

URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
FEODOTRACKER_FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
# FireHOL nivel 1: la recopilación más conservadora del proyecto (redes de
# spam, malware y bulletproof hosting con muy pocos falsos positivos). Publica
# RANGOS en CIDR, no IPs sueltas: por eso va a su propio archivo y lo lee
# IPRangeBlocklist, que busca por rango.
FIREHOL_FEED = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
    "firehol_level1.netset"
)

DOMAIN_OUTPUT_PATH = PROJECT_ROOT / "data" / "blocklist_feeds.txt"
IP_OUTPUT_PATH = PROJECT_ROOT / "data" / "ip_blocklist_feeds.txt"
RANGES_OUTPUT_PATH = PROJECT_ROOT / "data" / "ip_ranges_feeds.txt"


def fetch_urlhaus_domains() -> set[str]:
    """URLhaus publica un 'hostfile' en formato `0.0.0.0 dominio.com` - ya viene
    listo para usar como blocklist, solo hay que quedarse con la segunda columna."""
    domains: set[str] = set()
    try:
        response = http_client.get(URLHAUS_HOSTFILE, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                domains.add(parts[1].lower())
        feeds_status.registrar(DATA_DIR, "URLhaus", True, len(domains))
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar URLhaus: {exc}")
        feeds_status.registrar(DATA_DIR, "URLhaus", False, error=str(exc))
    return domains


def fetch_openphish_domains() -> set[str]:
    """OpenPhish publica URLs completas de phishing; extraemos solo el dominio
    de cada una (bloqueamos el dominio entero, no la URL puntual)."""
    domains: set[str] = set()
    try:
        response = http_client.get(OPENPHISH_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            hostname = urlsplit(line).hostname
            if hostname:
                domains.add(hostname.lower())
        feeds_status.registrar(DATA_DIR, "OpenPhish", True, len(domains))
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar OpenPhish: {exc}")
        feeds_status.registrar(DATA_DIR, "OpenPhish", False, error=str(exc))
    return domains


def fetch_feodotracker_ips() -> set[str]:
    """Feodo Tracker publica una lista de texto con una IP de C2 por línea
    (con comentarios que empiezan con #)."""
    ips: set[str] = set()
    try:
        response = http_client.get(FEODOTRACKER_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
        feeds_status.registrar(DATA_DIR, "Feodo Tracker", True, len(ips))
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar Feodo Tracker: {exc}")
        feeds_status.registrar(DATA_DIR, "Feodo Tracker", False, error=str(exc))
    return ips


def fetch_firehol_ranges() -> set[str]:
    """FireHOL nivel 1: rangos de red con mala reputación, en formato CIDR
    (una entrada por línea, comentarios con #)."""
    rangos: set[str] = set()
    try:
        response = http_client.get(FIREHOL_FEED, timeout=30)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                rangos.add(line)
        feeds_status.registrar(DATA_DIR, "FireHOL", True, len(rangos))
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar FireHOL: {exc}")
        feeds_status.registrar(DATA_DIR, "FireHOL", False, error=str(exc))
    return rangos


def is_stale(path: Path, min_interval_hours: float) -> bool:
    """True si el archivo no existe, o si pasó más tiempo que min_interval_hours
    desde la última vez que se generó."""
    if not path.exists():
        return True
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    return age_hours >= min_interval_hours


# Qué fracción de lo que había puede perder una lista de golpe antes de que
# asumamos que la descarga salió mal. Los feeds crecen y encogen todo el
# tiempo, pero pasar de 40.000 entradas a 3 no es que el feed encogió.
FRACCION_MINIMA = 0.5


def _entradas_previas(path: Path) -> int:
    """Cuántas entradas reales tenía la lista anterior."""
    if not path.exists():
        return 0
    total = 0
    for linea in path.read_text(encoding="utf-8", errors="replace").splitlines():
        linea = linea.strip()
        if linea and not linea.startswith("#"):
            total += 1
    return total


def parece_una_lista(items: set[str], validador) -> set[str]:
    """Se queda solo con las entradas que tienen forma de lo que se esperaba.

    Existe por un modo de falla concreto y bastante probable: un portal
    cautivo de wifi, un proxy corporativo o una página de mantenimiento
    responden **200 con HTML**. Los parsers de acá no distinguen, sacan
    basura del estilo `bgcolor="white">`, y como el conjunto no queda vacío
    la lista buena se sobreescribe con tres líneas de HTML. El panel de
    salud, encima, informa "OK, 3 reglas". Perder el bloqueo entero por
    conectarse a la wifi de un hotel es demasiado fácil.
    """
    return {item for item in items if validador(item)}


def _es_dominio(texto: str) -> bool:
    if not texto or len(texto) > 253 or " " in texto or "<" in texto or ">" in texto:
        return False
    if "." not in texto or texto.startswith(".") or texto.endswith("."):
        return False
    return all(
        parte and len(parte) <= 63 and all(c.isalnum() or c in "-_" for c in parte)
        for parte in texto.split(".")
    )


def _es_ip(texto: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


def _es_rango(texto: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(texto, strict=False)
        return True
    except ValueError:
        return False


def _write_list(path: Path, items: set[str], source_note: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    contenido = [
        "# Generado automáticamente por scripts/update_blocklist.py",
        f"# Fuentes: {source_note}. NO editar a mano: se sobreescribe.",
        f"# Total de entradas: {len(items)}",
        "",
    ]
    contenido += sorted(items)
    # Atómico: se escribe a un temporal y se renombra. El proxy recarga
    # estas listas cada 15 segundos desde otro hilo; con un `open(w)` normal
    # hay una ventana en la que la lista se lee vacía, y en esa ventana pasa
    # tráfico que debería bloquearse.
    fd, temporal = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(contenido) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporal, path)
    except BaseException:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise


def _guardar_si_tiene_sentido(path: Path, items: set[str], validador, nota: str, etiqueta: str) -> bool:
    """Guarda la lista solo si lo descargado parece de verdad esa lista."""
    limpias = parece_una_lista(items, validador)
    descartadas = len(items) - len(limpias)
    if descartadas:
        print(f"[update_blocklist] {etiqueta}: se descartaron {descartadas} entradas con formato raro")
    if not limpias:
        print(f"[update_blocklist] {etiqueta}: no vino nada usable, se deja la lista anterior")
        return False

    previas = _entradas_previas(path)
    if previas and len(limpias) < previas * FRACCION_MINIMA:
        print(
            f"[update_blocklist] {etiqueta}: vinieron {len(limpias)} entradas y antes "
            f"había {previas}. Es una caída demasiado brusca para ser real, así que "
            "se deja la lista anterior. Volvé a intentar desde otra red."
        )
        return False

    _write_list(path, limpias, nota)
    print(f"[update_blocklist] {etiqueta}: {len(limpias)} entradas guardadas en {path}")
    return True


def main(force: bool = False, min_interval_hours: float = 6) -> bool:
    """Descarga y regenera las listas. Devuelve True si efectivamente se
    actualizó algo, False si se omitió (por frescura) o falló todo."""

    if not force and not is_stale(DOMAIN_OUTPUT_PATH, min_interval_hours):
        print(
            f"[update_blocklist] Las listas se actualizaron hace menos de "
            f"{min_interval_hours}h, se omite la descarga."
        )
        return False

    print("[update_blocklist] Descargando feeds de amenazas (URLhaus + OpenPhish + Feodo Tracker + FireHOL)...")
    domains = fetch_urlhaus_domains() | fetch_openphish_domains()
    ips = fetch_feodotracker_ips()
    rangos = fetch_firehol_ranges()

    if not domains and not ips and not rangos:
        print(
            "[update_blocklist] No se obtuvo ningún dato (¿sin internet? "
            "¿los feeds están caídos?). No se modifican los archivos anteriores."
        )
        return False

    guardado = False
    if domains:
        guardado |= _guardar_si_tiene_sentido(
            DOMAIN_OUTPUT_PATH, domains, _es_dominio,
            "URLhaus (abuse.ch) + OpenPhish", "dominios")
    if ips:
        guardado |= _guardar_si_tiene_sentido(
            IP_OUTPUT_PATH, ips, _es_ip, "Feodo Tracker (abuse.ch)", "IPs de C2")
    if rangos:
        guardado |= _guardar_si_tiene_sentido(
            RANGES_OUTPUT_PATH, rangos, _es_rango, "FireHOL nivel 1", "rangos")

    return guardado


if __name__ == "__main__":
    # Corrido manualmente (o desde el menú): siempre fuerza la descarga.
    updated = main(force=True)
    if updated:
        print("[update_blocklist] Si el proxy ya estaba corriendo, se recarga solo (no hace falta reiniciar).")
