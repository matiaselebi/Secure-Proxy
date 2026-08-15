"""Actualiza las listas del proxy. Ya no baja nada: se lo pide a Secure-Intel.

QUÉ PASÓ CON ESTE ARCHIVO

Tenía casi 300 líneas: la URL de URLhaus, la de OpenPhish, la de Feodo
Tracker, la de FireHOL, y una función de descarga y parseo para cada una.
SecureDNS tenía las mismas URLs escritas de nuevo en su propio archivo.

Ese duplicado ya nos costó una vez: el día que un feed cambie de URL, arreglás
uno, verificás que anda, y el otro se queda bajando un 404 en silencio. El
archivo viejo sigue ahí, el panel sigue diciendo que hay 40.000 reglas, y nadie
se entera hasta que pasa algo.

**Secure-Intel es el único lugar donde vive la URL de un feed.** Baja, valida
que no haya encogido de golpe, detecta feeds congelados, y deja los mismos
archivos de texto que este proxy ya leía. Su formato no cambió: lo único que
cambió es de dónde salen esos bytes.

Es la fase 2 del punto 8: borrarle a SecureProxy lo que ahora hacen otros.

QUÉ PASA SI SECURE-INTEL NO ESTÁ

**Se dice y se falla.** No hay camino de respaldo, y es a propósito: un
respaldo que baja feeds por su cuenta es exactamente el duplicado que se vino
a sacar, y encima uno que solo se usa cuando nadie está mirando.

Antes había uno. La diferencia entre entonces y ahora es que Secure-Intel ya
está probado y es el que alimenta también a SecureDNS y a SecureHIPS: si falta,
lo que hay que hacer es clonarlo, no que cada herramienta se arregle sola.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import intel_puente  # noqa: E402


def main(force: bool = False, min_interval_hours: float = 6) -> bool:
    """Le pide a Secure-Intel que actualice. True si se actualizó algo.

    `min_interval_hours` se conserva en la firma porque el proxy llama a esto
    desde su ciclo de fondo, pero quien decide si hace falta bajar de nuevo es
    Secure-Intel, que lleva la cuenta por fuente y no por archivo. Una sola
    cosa decidiendo es lo que evita que dos programas bajen el mismo feed con
    veinte minutos de diferencia.
    """
    if not intel_puente.disponible():
        print("[update_blocklist] NO actualicé nada: falta Secure-Intel.")
        print("[update_blocklist] Es el que baja los feeds para toda la suite.")
        print("[update_blocklist] Clonalo como carpeta hermana de este proyecto:")
        print("    git clone <tu-repo>/secure-intel")
        print("[update_blocklist] Las listas que ya estaban siguen funcionando.")
        return False

    if intel_puente.actualizar(forzar=force):
        print("[update_blocklist] listas actualizadas por Secure-Intel")
        return True

    print("[update_blocklist] Secure-Intel no pudo actualizar esta vez; "
          "se dejaron las listas anteriores")
    return False


if __name__ == "__main__":
    forzar = "--force" in sys.argv or "--forzar" in sys.argv
    raise SystemExit(0 if main(force=forzar) else 1)
