"""Las listas ya no las baja el proxy: se las pide a Secure-Intel.

Este archivo tenía tests de parseo para cada feed: el hostfile de URLhaus, las
URLs de OpenPhish, la lista de Feodo. Se fueron con el código que probaban.

No es que esos casos dejaron de importar: **se mudaron**. Ahora los prueba
Secure-Intel, que es el único que baja, y encima con cosas que acá no había:
que un feed no haya encogido de golpe, que no esté congelado devolviendo lo
mismo hace días, y que una fuente caída no pise los datos anteriores.

Lo que queda por probar acá es lo único que hace este script: delegar bien, y
sobre todo **fallar de forma visible cuando no puede delegar**.
"""

import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))
sys.path.insert(0, str(RAIZ / "scripts"))

import update_blocklist  # noqa: E402


def test_le_pide_a_intel_y_avisa(monkeypatch, capsys):
    monkeypatch.setattr(update_blocklist.intel_puente, "disponible", lambda: True)
    monkeypatch.setattr(update_blocklist.intel_puente, "actualizar",
                        lambda forzar=False: True)
    assert update_blocklist.main() is True
    assert "Secure-Intel" in capsys.readouterr().out


def test_sin_intel_no_baja_nada_y_lo_dice(monkeypatch, capsys):
    """No hay camino de respaldo, y es a propósito: un respaldo que baja feeds
    por su cuenta es exactamente el duplicado que se vino a sacar, y encima
    uno que solo se usa cuando nadie está mirando."""
    monkeypatch.setattr(update_blocklist.intel_puente, "disponible", lambda: False)

    def no_deberia(*_a, **_k):
        raise AssertionError("no tenía que intentar bajar nada por su cuenta")

    monkeypatch.setattr(update_blocklist.intel_puente, "actualizar", no_deberia)

    assert update_blocklist.main() is False
    salida = capsys.readouterr().out
    assert "falta Secure-Intel" in salida
    # Dice qué hacer, no solo que falló.
    assert "git clone" in salida
    # Y aclara que lo que ya estaba sigue sirviendo: una lista vieja protege
    # menos que una nueva, pero muchísimo más que ninguna.
    assert "siguen funcionando" in salida


def test_si_intel_falla_se_dejan_las_listas_viejas(monkeypatch, capsys):
    monkeypatch.setattr(update_blocklist.intel_puente, "disponible", lambda: True)
    monkeypatch.setattr(update_blocklist.intel_puente, "actualizar",
                        lambda forzar=False: False)
    assert update_blocklist.main() is False
    assert "listas anteriores" in capsys.readouterr().out


def test_ya_no_queda_ninguna_url_de_feed_en_el_proxy():
    """El test de "no vuelvas a hacerlo".

    Tener la misma URL escrita en dos proyectos ya costó caro: el día que un
    feed cambie de dirección, arreglás uno, verificás que anda, y el otro se
    queda bajando un 404 en silencio mientras el panel dice que hay 40.000
    reglas.

    Se miran los literales de CÓDIGO y no el texto del archivo. La primera
    versión buscaba las palabras en el fuente y encontraba los comentarios que
    explican justamente por qué esas descargas se sacaron. Un test que no
    distingue una línea de código de una línea de prosa no está probando el
    código, y encima castiga documentar.
    """
    import ast

    FEEDS = ("urlhaus.abuse.ch", "openphish.com", "feodotracker.abuse.ch",
             "iplists.firehol.org", "check.torproject.org")
    fuentes = list((RAIZ / "src" / "secureproxy").glob("*.py"))
    fuentes += list((RAIZ / "scripts").glob("*.py"))

    culpables = []
    for archivo in fuentes:
        arbol = ast.parse(archivo.read_text(encoding="utf-8"))
        # Los docstrings son el primer hijo de módulo, clase o función: se
        # sacan del análisis y se mira todo lo demás.
        docstrings = set()
        for nodo in ast.walk(arbol):
            if isinstance(nodo, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                primero = (nodo.body or [None])[0]
                if (isinstance(primero, ast.Expr)
                        and isinstance(primero.value, ast.Constant)
                        and isinstance(primero.value.value, str)):
                    docstrings.add(id(primero.value))
        for nodo in ast.walk(arbol):
            if (isinstance(nodo, ast.Constant) and isinstance(nodo.value, str)
                    and id(nodo) not in docstrings):
                for feed in FEEDS:
                    if feed in nodo.value:
                        culpables.append(f"{archivo.name}: {feed}")
    assert culpables == [], (
        "las URLs de los feeds viven SOLO en Secure-Intel: " + "; ".join(culpables))
