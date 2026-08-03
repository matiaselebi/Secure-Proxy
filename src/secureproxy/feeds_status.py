"""Estado de cada fuente de amenazas, para el panel de salud del dashboard.

Por qué existe un archivo aparte y no se deduce de las listas: URLhaus y
OpenPhish escriben en el MISMO archivo (`blocklist_feeds.txt`), así que la
fecha de ese archivo no alcanza para saber si las dos anduvieron o si una
falló y la otra tapó el problema. Guardando el resultado de cada descarga por
separado, el panel puede decir la verdad: cuál anduvo, cuándo, y cuántas
reglas aportó cada una.

El archivo es un JSON chiquito en `data/feeds_status.json`. Si no existe -por
ejemplo la primera vez, antes de la primera actualización- el panel muestra
"sin datos todavía" en vez de inventar un estado.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

ARCHIVO = "feeds_status.json"


def _ruta(data_dir: str | Path) -> Path:
    return Path(data_dir) / ARCHIVO


def resumir_error(error: str) -> str:
    """Traduce el error crudo de la librería a una línea entendible.

    Un fallo de descarga viene con 300 caracteres de traza
    ("HTTPSConnectionPool(host='urlhaus.abuse.ch', port=443): Max retries
    exceeded with url: ... SSLCertVerificationError..."). Volcado tal cual en
    el panel es ilegible y no ayuda a decidir qué hacer. Acá se reconoce el
    tipo de problema y se dice en una línea; el detalle completo igual queda
    impreso en la consola del proxy para cuando haga falta.
    """
    bajo = (error or "").lower()
    if not bajo:
        return "no se pudo descargar"
    if "certificate" in bajo or "sslerror" in bajo or "ssl:" in bajo:
        return "el certificado del sitio no validó (¿antivirus o proxy inspeccionando TLS?)"
    if "getaddrinfo" in bajo or "nameresolution" in bajo or "resolve" in bajo:
        return "no se pudo resolver el nombre (¿sin DNS?)"
    if "timed out" in bajo or "timeout" in bajo:
        return "tardó demasiado en responder"
    if "connection" in bajo or "refused" in bajo or "unreachable" in bajo:
        return "no se pudo conectar (¿sin internet?)"
    for codigo in ("403", "404", "429", "500", "502", "503"):
        if codigo in bajo:
            return f"el servidor respondió {codigo}"
    return error.strip()[:90]


def registrar(
    data_dir: str | Path,
    fuente: str,
    ok: bool,
    entradas: int = 0,
    error: str = "",
) -> None:
    """Anota cómo salió la última descarga de una fuente.

    Se conserva `ultimo_ok` aunque la descarga de ahora haya fallado: saber
    que URLhaus falló recién pero que la lista que está en uso es de hace dos
    horas es MUY distinto de no tener nada. El panel muestra las dos cosas.
    """
    ruta = _ruta(data_dir)
    datos = leer(data_dir)
    anterior = datos.get(fuente, {})
    ahora = datetime.now(timezone.utc).isoformat()

    datos[fuente] = {
        "ok": bool(ok),
        "ultimo_intento": ahora,
        "ultimo_ok": ahora if ok else anterior.get("ultimo_ok", ""),
        "entradas": int(entradas) if ok else int(anterior.get("entradas", 0)),
        "error": "" if ok else resumir_error(error),
    }
    try:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text(
            json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        # No poder anotar el estado no puede romper una actualización de
        # listas que sí funcionó.
        pass


def leer(data_dir: str | Path) -> dict:
    try:
        return json.loads(_ruta(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
