"""Fase 1 del punto 8: el proxy dice dónde sirve y dónde no.

La tentación era dejarlo correr en el servidor "por las dudas". Lo que pasa
si lo dejás es peor que no tenerlo: un panel con conexiones y bloqueos que
solo son los del propio servidor, mientras el celular, la consola y el
televisor salen por afuera sin que nada lo diga.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import alcance  # noqa: E402


def test_en_windows_siempre_corresponde(monkeypatch):
    monkeypatch.setattr(alcance.platform, "system", lambda: "Windows")
    assert alcance.corresponde()
    assert alcance.aviso() == ""


def test_en_linux_con_pantalla_corresponde(monkeypatch):
    monkeypatch.setattr(alcance.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    assert alcance.corresponde()


def test_en_un_servidor_headless_no_corresponde(monkeypatch):
    monkeypatch.setattr(alcance.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert not alcance.corresponde()


def test_el_aviso_explica_el_agujero_y_a_donde_ir(monkeypatch):
    """No alcanza con decir "no va acá": hay que decir qué queda sin cubrir y
    cuál es la pieza que sí lo cubre, o el aviso se ignora."""
    monkeypatch.setattr(alcance.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    texto = alcance.aviso()
    assert "celulares" in texto and "consolas" in texto
    assert "SecureDNS" in texto


def test_no_apaga_nada_solo_avisa(monkeypatch):
    """El proxy sigue arrancando en un servidor: hay un caso legítimo (mirar
    lo que sale del propio servidor). Lo que no puede pasar es que arranque
    callado y parezca que cubre la casa."""
    monkeypatch.setattr(alcance.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert isinstance(alcance.aviso(), str)
    assert alcance.como_capacidad()["estado"] == "na"


def test_la_capacidad_entra_en_el_formato_de_diagnostico(monkeypatch):
    monkeypatch.setattr(alcance.platform, "system", lambda: "Windows")
    cap = alcance.como_capacidad()
    assert set(cap) == {"nombre", "estado", "detalle", "arreglo"}
    assert cap["estado"] == "ok"
