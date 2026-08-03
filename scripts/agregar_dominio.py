#!/usr/bin/env python3
"""Agrega un dominio a la lista blanca o a la negra manual.

Existe como script y no como un `python -c` dentro del .bat por un motivo de
seguridad concreto. Antes el menú hacía esto:

    python -c "... normalizar_dominio('%NUEVO_DOMINIO%') ..."

y ahí el texto que uno escribe en el prompt quedaba interpolado DENTRO del
código fuente de Python. La validación corría después, cuando el intérprete
ya había evaluado la expresión. O sea: pegar en ese prompt un "dominio"
armado con comillas ejecutaba código arbitrario, con los permisos del .bat,
que se corre como administrador. Y el propio prompt invita a pegar.

Pasando el dominio como argumento (sys.argv) el texto es un dato y nunca
código, sin importar qué traiga.

Uso:
    python scripts/agregar_dominio.py blanca ejemplo.com
    python scripts/agregar_dominio.py negra https://www.ejemplo.com/algo
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from secureproxy.threat_intel import Allowlist, Blocklist  # noqa: E402
from secureproxy.validation import is_valid_domain, normalizar_dominio  # noqa: E402

LISTAS = {
    "blanca": (Allowlist, "data/allowlist.txt", "lista blanca"),
    "negra": (Blocklist, "data/blocklist.txt", "lista negra manual"),
}


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in LISTAS:
        print("Uso: agregar_dominio.py [blanca|negra] <dominio o URL>")
        return 2

    clase, ruta, etiqueta = LISTAS[argv[1]]
    crudo = " ".join(argv[2:]).strip()
    dominio, avisos = normalizar_dominio(crudo)
    if not is_valid_domain(dominio):
        print(f"No pude entender \"{crudo}\" como un dominio.")
        print("Ejemplos que sí funcionan: ejemplo.com, https://www.ejemplo.com/algo, 8.8.8.8")
        return 1

    clase(str(PROJECT_ROOT / ruta)).add_and_reload(dominio)
    print(f"Agregado a la {etiqueta}: {dominio}")
    for aviso in avisos:
        print(f"  - {aviso}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
