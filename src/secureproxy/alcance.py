"""Hasta dónde llega este proxy, dicho por el proxy mismo.

FASE 1 DEL PUNTO 8: SACARLO DEL SERVIDOR

SecureProxy es un proxy explícito: protege a las aplicaciones que están
configuradas para pasar por él. En una PC de escritorio eso alcanza, porque
ahí SecureCenter puede poner el proxy del sistema y el navegador lo hereda.

En un servidor o en el router de la casa, no. Un celular no se configura solo
para pasar por un proxy, una consola no tiene dónde configurarlo, y un
televisor tampoco. Ponerlo ahí da una pantalla con números que solo cubren al
puñado de programas que corren en el propio servidor, y eso es peor que no
tener nada: parece cobertura de toda la casa y no lo es.

Lo que sí cubre a toda la casa es el DNS, porque los equipos lo agarran del
router sin que nadie los toque uno por uno. Por eso el que va en el servidor
es SecureDNS sobre Pi-hole, y el proxy se queda en el escritorio.

POR QUÉ ESTO ES UN ARCHIVO Y NO UN RENGLÓN DEL README

Porque un README no se lee cuando el proxy ya está corriendo. Esto se imprime
al arrancar y lo lee SecureCenter para no prenderlo donde no corresponde: la
decisión queda escrita en un lugar que el programa consulta, y no en un lugar
donde alguien tendría que acordarse de mirar.
"""

import os
import platform

ESCRITORIO = "escritorio"
SERVIDOR = "servidor"


def hay_escritorio() -> bool:
    """¿Esta máquina tiene a alguien sentado adelante?

    En Windows se asume que sí: no existe la instalación de escritorio sin
    escritorio. En Linux se mira si hay servidor gráfico, que es lo más
    parecido a la pregunta real y no requiere adivinar la distribución.
    """
    if platform.system() == "Windows":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def donde_estoy() -> str:
    return ESCRITORIO if hay_escritorio() else SERVIDOR


def corresponde() -> bool:
    """¿Este es un equipo donde SecureProxy tiene sentido?"""
    return donde_estoy() == ESCRITORIO


def aviso() -> str:
    """La frase para imprimir al arrancar. Vacía cuando está donde va."""
    if corresponde():
        return ""
    return (
        "SecureProxy está corriendo en un equipo sin escritorio. Es un proxy "
        "explícito: solo cubre a los programas de ESTA máquina configurados "
        "para pasar por él. No cubre celulares, consolas ni televisores, "
        "porque a esos no hay dónde configurarles un proxy. Si lo que querés "
        "es cubrir la casa entera, el que hace eso es SecureDNS sobre Pi-hole, "
        "que los equipos agarran del router sin tocarlos uno por uno."
    )


def como_capacidad() -> dict:
    """El mismo dato en el formato de `diagnostico.py` de SecureCenter."""
    if corresponde():
        return {"nombre": "Alcance de SecureProxy", "estado": "ok",
                "detalle": ("equipo de escritorio: el proxy del sistema hace "
                            "que el navegador pase por acá"),
                "arreglo": ""}
    return {"nombre": "Alcance de SecureProxy", "estado": "na",
            "detalle": aviso(),
            "arreglo": "corré SecureProxy en tu PC, y en el servidor dejá SecureDNS"}
