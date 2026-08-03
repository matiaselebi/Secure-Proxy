"""Validación básica de formato de dominio para los formularios del
dashboard y las opciones del menú .bat que agregan a la allowlist/blocklist.

No es una validación exhaustiva de RFC 1035 (no hace falta: si alguien
escribe algo raro a mano, el objetivo es solo evitar basura obvia en los
archivos de listas - espacios, cadenas vacías, protocolos/paths pegados
por error al copiar una URL - no blindar contra un input adversarial,
porque estos formularios ya son de uso exclusivamente local)."""

import ipaddress
import re

_ESQUEMA_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
)


def normalizar_dominio(texto: str) -> tuple[str, list[str]]:
    """Convierte lo que sea que hayan pegado en un dominio limpio.

    Nadie copia dominios: uno copia la barra del navegador, y de ahí sale
    "https://www.ejemplo.com/algo?x=1". Antes eso se rechazaba y había que
    editarlo a mano, que es exactamente el momento en que uno se equivoca.

    Devuelve `(dominio, avisos)`. Los avisos explican qué se le sacó, para
    poder mostrárselo en pantalla: una lista de bloqueo que calladamente
    guarda algo distinto de lo que escribiste es una fuente de sorpresas.

    Lo que saca, y por qué:

    - **El esquema** (`https://`): el proxy filtra por destino, y el
      destino es el mismo se llegue por http o por https.
    - **El camino** (`/algo`): esto NO es una simplificación, es una
      limitación real. En HTTPS el proxy solo ve el CONNECT con el host; el
      camino viaja adentro del TLS y nunca se ve (ver ADR 0001). Una regla
      con camino no podría aplicarse, así que se bloquea el dominio entero
      y se avisa.
    - **El puerto** (`:8443`): las listas son por destino, no por puerto.
    - **El `www.`**: `www.ejemplo.com` y `ejemplo.com` son el mismo lugar
      para cualquiera que mire la lista. Guardar el dominio sin `www.` hace
      que la regla cubra las dos formas, porque las listas ya matchean
      subdominios.
    """
    avisos: list[str] = []
    dominio = (texto or "").strip().lower()
    if not dominio:
        return "", avisos

    if _ESQUEMA_RE.match(dominio):
        dominio = _ESQUEMA_RE.sub("", dominio, count=1)
        avisos.append("se sacó el http/https")

    # Credenciales pegadas en la URL (usuario:clave@host). Raro, pero si
    # aparece hay que quedarse con el host, no con el usuario.
    if "@" in dominio:
        dominio = dominio.rsplit("@", 1)[1]

    for corte in ("/", "?", "#"):
        if corte in dominio:
            resto = dominio.split(corte, 1)[1]
            dominio = dominio.split(corte, 1)[0]
            if corte == "/" and resto:
                avisos.append(
                    "se sacó el camino después de la barra: en HTTPS el proxy "
                    "solo ve el dominio, así que la regla cubre el sitio entero"
                )

    # Puerto. Ojo con IPv6 entre corchetes, que lleva ":" adentro.
    if not dominio.startswith("[") and dominio.count(":") == 1:
        cabeza, _, cola = dominio.partition(":")
        if cola.isdigit():
            dominio = cabeza
            avisos.append("se sacó el puerto")

    dominio = dominio.strip(".")

    if dominio.startswith("www.") and len(dominio) > 4:
        dominio = dominio[4:]
        avisos.append("se sacó el www. (la regla cubre igual www. y sin www.)")

    return dominio, avisos


def limpiar_para_mostrar(host: str) -> str:
    """El dominio como conviene LEERLO en una tabla: sin `www.`.

    Es solo presentación. El host real, tal cual se conectó, sigue guardado
    y se ve completo en el detalle de la conexión: acá se saca el prefijo
    que se repite en media pantalla y no aporta nada para distinguir una
    fila de otra.
    """
    limpio = (host or "").strip()
    if limpio.lower().startswith("www.") and len(limpio) > 4:
        return limpio[4:]
    return limpio


def normalizar_host_de_trafico(host: str) -> str:
    """El host tal como hay que compararlo contra las listas.

    Existe por un bypass de un solo carácter. El DNS trata "nanopool.org."
    (con punto final, que es la forma absoluta de un FQDN) y "nanopool.org"
    como el mismo nombre, y resuelven a la misma IP; pero las listas comparan
    texto, así que con el punto al final no matcheaba nada y la conexión
    pasaba limpita. Pasaba igual con los nombres internacionales, que se
    comparaban en Unicode mientras los feeds los publican en punycode.

    Se aplica ANTES de evaluar y también antes de conectar, para no dejar la
    otra mitad del problema: filtrar un nombre y conectarse a otro.
    """
    limpio = (host or "").strip().strip(".").lower()
    if not limpio:
        return ""
    try:
        # IDNA deja los nombres internacionales en la misma forma en que los
        # publican los feeds. Si falla (etiqueta demasiado larga, caracteres
        # raros) se devuelve lo que había: es preferible comparar algo
        # imperfecto a no comparar nada.
        return limpio.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return limpio


def is_valid_domain(domain: str) -> bool:
    """True si `domain` tiene forma de nombre de dominio (letras/números/
    guiones separados por puntos, con un TLD alfabético al final) o de
    dirección IPv4/IPv6 literal (el proxy también puede filtrar por IP
    directa, no solo por nombre). Rechaza cadenas vacías, con espacios, con
    "http://" o rutas pegadas, o con caracteres fuera de lo esperado."""
    domain = domain.strip().lower()
    if not domain or " " in domain:
        return False
    if "/" in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass
    if ":" in domain:
        return False
    return bool(_DOMAIN_RE.match(domain))
