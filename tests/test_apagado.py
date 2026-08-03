"""El botón "Apagar proxy" del panel.

Lo que se prueba acá no es que un botón exista, sino las tres cosas que
pueden salir mal con un endpoint que mata el proceso: que lo dispare
cualquier página web, que conteste después de morirse (y el navegador
muestre un error cuando en realidad funcionó), y que aparezca en paneles
donde no hay nada que apagar.
"""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_dashboard_server  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
)


def _motor(tmp_path):
    (tmp_path / "bl.txt").write_text("malicioso.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    return FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )


def _levantar(tmp_path, apagar):
    engine = _motor(tmp_path)
    servidor = build_dashboard_server(
        "127.0.0.1", 0, engine, LoggerDB(str(tmp_path / "l.db")),
        TelegramNotifier(False, "", ""), FirewallManager(False), engine.allowlist,
        apagar=apagar,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return servidor


def _pedir(puerto, ruta, cabeceras="", espera=4.0) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=espera)
    try:
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
            f"{cabeceras}Connection: close\r\n\r\n".encode()
        )
        con.settimeout(espera)
        datos = b""
        try:
            while len(datos) < 262144:
                trozo = con.recv(8192)
                if not trozo:
                    break
                datos += trozo
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


@pytest.fixture()
def avisado(tmp_path):
    """Panel con un apagado de mentira: en vez de matar el proceso, marca un
    evento. Así se puede comprobar el pedido sin tumbar la corrida de tests."""
    llamadas = []
    servidor = _levantar(tmp_path, lambda: llamadas.append(time.monotonic()))
    try:
        yield servidor.server_address[1], llamadas
    finally:
        servidor.shutdown()


def test_apagar_contesta_antes_de_apagar(avisado):
    """El orden importa: si el proceso se cerrara antes de mandar la
    respuesta, el navegador mostraría "no se puede conectar" justo cuando la
    acción salió bien, y el usuario volvería a apretar pensando que falló."""
    puerto, llamadas = avisado

    respuesta = _pedir(puerto, "/apagar")

    assert "200" in respuesta.split("\r\n")[0]
    assert "SecureProxy apagado" in respuesta
    # Cuando la respuesta ya está en la mano, el apagado todavía no se pidió.
    assert llamadas == []


def test_apagar_pide_el_apagado_despues(avisado):
    puerto, llamadas = avisado

    _pedir(puerto, "/apagar")
    for _ in range(40):
        if llamadas:
            break
        time.sleep(0.1)

    assert len(llamadas) == 1


def test_la_pagina_avisa_que_el_navegador_sigue_apuntando_al_proxy(avisado):
    """El efecto que sorprende no es que el proxy se apague, es que después no
    anda internet: el navegador sigue configurado para pasar por él."""
    puerto, _llamadas = avisado

    respuesta = _pedir(puerto, "/apagar")

    assert "sigue apuntando al proxy" in respuesta
    assert "run_proxy.py" in respuesta


def test_el_boton_esta_en_el_panel(avisado):
    puerto, _llamadas = avisado

    panel = _pedir(puerto, "/")

    assert 'action="/apagar"' in panel
    assert "Apagar proxy" in panel


def test_una_web_cualquiera_no_puede_apagar_el_proxy(avisado):
    """Es el mismo agujero de CSRF que el resto de las acciones del panel,
    pero con la peor consecuencia posible: un <img src=...> en cualquier
    página y te quedás sin filtrado."""
    puerto, llamadas = avisado

    respuesta = _pedir(
        puerto, "/apagar",
        "Sec-Fetch-Site: cross-site\r\nOrigin: https://sitio-malicioso.com\r\n",
    )
    time.sleep(1.0)

    assert "403" in respuesta.split("\r\n")[0]
    assert llamadas == []


def test_tampoco_por_referer_de_otro_sitio(avisado):
    puerto, llamadas = avisado

    respuesta = _pedir(
        puerto, "/apagar", "Referer: https://sitio-malicioso.com/pagina\r\n",
    )
    time.sleep(1.0)

    assert "403" in respuesta.split("\r\n")[0]
    assert llamadas == []


def test_sin_forma_de_apagar_no_se_muestra_el_boton(tmp_path):
    """Cuando el panel corre embebido en otro programa (o en un test) no hay
    proceso propio que cerrar. Un botón que no hace nada es peor que no
    tenerlo."""
    servidor = _levantar(tmp_path, None)
    try:
        puerto = servidor.server_address[1]
        panel = _pedir(puerto, "/")
        assert 'action="/apagar"' not in panel
        assert "Apagar proxy" not in panel
    finally:
        servidor.shutdown()


def test_sin_forma_de_apagar_la_ruta_lo_dice_y_no_rompe(tmp_path):
    servidor = _levantar(tmp_path, None)
    try:
        respuesta = _pedir(servidor.server_address[1], "/apagar")
        # Redirige de vuelta al panel con el aviso, no tira un 500.
        assert "303" in respuesta.split("\r\n")[0]
        assert "aviso=" in respuesta
    finally:
        servidor.shutdown()
