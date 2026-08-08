"""El cliente que le pide bloqueos a SecureHIPS.

Lo que más importa probar acá no es el camino feliz, sino que el proxy NO se
rompa cuando SecureHIPS no está. Una integración que deja al proxy colgado o
sin bloquear porque la otra herramienta está apagada es peor que no tener
integración.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.hips_client import ClienteHIPS  # noqa: E402

TOKEN = "token-compartido-de-prueba"


class HipsFalso(BaseHTTPRequestHandler):
    """Un SecureHIPS de mentira que anota lo que le llega."""

    recibidos: list = []
    respuesta: dict = {"ok": True, "aplicado": True, "hasta": 0, "motivo": "x",
                       "modo": "aplicar"}
    codigo: int = 200

    def log_message(self, *a):  # noqa: A002
        pass

    def do_POST(self):  # noqa: N802
        largo = int(self.headers.get("Content-Length") or 0)
        cuerpo = json.loads(self.rfile.read(largo) or b"{}")
        HipsFalso.recibidos.append({
            "ruta": self.path,
            "auth": self.headers.get("Authorization"),
            "cuerpo": cuerpo,
        })
        salida = json.dumps(HipsFalso.respuesta).encode("utf-8")
        self.send_response(HipsFalso.codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(salida)))
        self.end_headers()
        self.wfile.write(salida)


@pytest.fixture()
def hips():
    HipsFalso.recibidos = []
    HipsFalso.codigo = 200
    HipsFalso.respuesta = {"ok": True, "aplicado": True, "hasta": 0,
                           "motivo": "x", "modo": "aplicar"}
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), HipsFalso)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{servidor.server_address[1]}"
    finally:
        servidor.shutdown()


# ------------------------------------------------------- cuándo ni intenta


def test_sin_token_no_intenta_nada():
    cliente = ClienteHIPS(url="http://127.0.0.1:9", token="")
    tomado, detalle = cliente.bloquear("1.2.3.4")
    assert not tomado
    assert "SECUREHIPS_API_TOKEN" in detalle


def test_sin_url_no_intenta_nada():
    cliente = ClienteHIPS(url="", token=TOKEN)
    assert not cliente.configurado()
    assert not cliente.bloquear("1.2.3.4")[0]


# --------------------------------------------------------- el camino feliz


def test_manda_el_token_en_un_header_y_no_en_la_url(hips):
    """En la URL terminaría en los logs y en el historial del navegador."""
    ClienteHIPS(url=hips, token=TOKEN).bloquear("203.0.113.7", motivo="dominio malo")
    pedido = HipsFalso.recibidos[0]
    assert pedido["auth"] == f"Bearer {TOKEN}"
    assert TOKEN not in pedido["ruta"]


def test_manda_la_ip_el_origen_y_el_motivo(hips):
    ClienteHIPS(url=hips, token=TOKEN).bloquear("203.0.113.8", motivo="algo feo")
    cuerpo = HipsFalso.recibidos[0]["cuerpo"]
    assert cuerpo["ip"] == "203.0.113.8"
    assert cuerpo["origen"] == "secureproxy"
    assert cuerpo["motivo"] == "algo feo"


def test_si_el_hips_lo_toma_avisa_que_lo_tomo(hips):
    tomado, detalle = ClienteHIPS(url=hips, token=TOKEN).bloquear("203.0.113.9")
    assert tomado
    assert "SecureHIPS" in detalle


def test_en_modo_audit_lo_dice(hips):
    HipsFalso.respuesta = {"ok": True, "aplicado": False, "modo": "audit"}
    tomado, detalle = ClienteHIPS(url=hips, token=TOKEN).bloquear("203.0.113.10")
    assert tomado
    assert "NO la bloqueó" in detalle and "audit" in detalle


def test_si_esta_en_la_lista_blanca_del_hips_el_proxy_no_la_bloquea(hips):
    """El caso más importante de todos.

    Si el HIPS dice «no, está en mi lista blanca», el proxy tiene que aceptar
    esa respuesta. Bloquearla por su cuenta sería justamente saltearse la
    lista blanca, que es lo que esta integración vino a arreglar.
    """
    HipsFalso.respuesta = {"ok": False, "razon": "está en la lista blanca: la impresora"}
    tomado, detalle = ClienteHIPS(url=hips, token=TOKEN).bloquear("198.51.100.5")
    assert tomado
    assert "lista blanca" in detalle


# ------------------------------------------------ cuando el HIPS no está


def test_si_el_hips_no_esta_el_proxy_sigue_solo():
    """Puerto cerrado: falla al instante y devuelve «encargate vos»."""
    cliente = ClienteHIPS(url="http://127.0.0.1:9", token=TOKEN, timeout=0.5)
    tomado, detalle = cliente.bloquear("203.0.113.11")
    assert not tomado
    assert "no pude hablar" in detalle


def test_despues_de_tres_fallas_deja_de_intentar():
    """El fusible: esto se llama desde el camino de una conexión."""
    cliente = ClienteHIPS(url="http://127.0.0.1:9", token=TOKEN, timeout=0.5)
    for _ in range(3):
        cliente.bloquear("203.0.113.12")
    _, detalle = cliente.bloquear("203.0.113.13")
    assert "no lo intento por un rato" in detalle


def test_un_rechazo_del_hips_no_abre_el_fusible(hips):
    """Un 401 no es «está caído»: está vivo y dijo que no."""
    HipsFalso.codigo = 401
    cliente = ClienteHIPS(url=hips, token=TOKEN)
    for _ in range(5):
        tomado, detalle = cliente.bloquear("203.0.113.14")
        assert not tomado
        assert "rechazó" in detalle
    assert len(HipsFalso.recibidos) == 5


# -------------------------------------------- integración con el firewall


def test_si_el_hips_lo_toma_el_proxy_no_escribe_ninguna_regla(hips):
    """Una regla puesta por los dos lados es una que el HIPS no puede levantar."""
    fw = FirewallManager(enabled=False, hips=ClienteHIPS(url=hips, token=TOKEN))
    salida = fw.block_ip("203.0.113.15")
    assert "SecureHIPS" in salida
    assert "netsh" not in salida and "iptables" not in salida


def test_si_el_hips_no_esta_el_proxy_arma_la_regla_como_siempre():
    fw = FirewallManager(
        enabled=False,
        hips=ClienteHIPS(url="http://127.0.0.1:9", token=TOKEN, timeout=0.5),
    )
    salida = fw.block_ip("203.0.113.16")
    assert "netsh" in salida or "iptables" in salida


def test_sin_cliente_configurado_el_firewall_anda_igual_que_antes():
    """La compatibilidad hacia atrás: nadie tiene que enganchar el HIPS."""
    assert "203.0.113.17" in FirewallManager(enabled=False).block_ip("203.0.113.17")


def test_una_ip_invalida_no_llega_ni_al_hips(hips):
    fw = FirewallManager(enabled=False, hips=ClienteHIPS(url=hips, token=TOKEN))
    assert "no es una IP valida" in fw.block_ip("no-soy-una-ip")
    assert not HipsFalso.recibidos
