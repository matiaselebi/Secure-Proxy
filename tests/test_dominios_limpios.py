"""Limpieza de dominios: aceptar lo que uno pega, mostrar lo que uno lee.

Dos cosas distintas que conviene no confundir:

- **Normalizar al ENTRAR** (`normalizar_dominio`): cambia lo que se guarda
  en el archivo de lista. Una entrada como "https://www.x.com/algo" no
  matchea nunca, porque el proxy compara contra el host: era una regla que
  parecía puesta y no hacía nada.
- **Limpiar al MOSTRAR** (`limpiar_para_mostrar`): no cambia ningún dato,
  solo saca el "www." de la tabla. El host real sigue completo en el detalle
  de la conexión.
"""

import sys
import threading
import urllib.request
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
from secureproxy.validation import (  # noqa: E402
    is_valid_domain,
    limpiar_para_mostrar,
    normalizar_dominio,
)

ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def pedir(url):
    with ABRIDOR.open(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


# ---------------- normalizar al entrar ----------------


@pytest.mark.parametrize(
    "pegado,esperado",
    [
        ("https://www.ejemplo.com/algo?x=1", "ejemplo.com"),
        ("http://ejemplo.com", "ejemplo.com"),
        ("www.google-analytics.com", "google-analytics.com"),
        ("ejemplo.com:8443", "ejemplo.com"),
        ("EJEMPLO.COM/", "ejemplo.com"),
        ("https://user:clave@sitio.com/x", "sitio.com"),
        ("  ejemplo.com  ", "ejemplo.com"),
        ("ejemplo.com.", "ejemplo.com"),
        ("https://sub.dominio.com.ar/categoria/nota", "sub.dominio.com.ar"),
        ("8.8.8.8", "8.8.8.8"),
        ("http://8.8.8.8:3128/", "8.8.8.8"),
    ],
)
def test_lo_que_uno_pega_del_navegador_queda_como_dominio(pegado, esperado):
    limpio, _avisos = normalizar_dominio(pegado)

    assert limpio == esperado
    assert is_valid_domain(limpio)


def test_solo_se_saca_el_www_del_principio():
    """Sacar cualquier 'www' rompería dominios legítimos."""
    assert normalizar_dominio("www.ejemplo.com")[0] == "ejemplo.com"
    assert normalizar_dominio("algo.www.ejemplo.com")[0] == "algo.www.ejemplo.com"
    assert normalizar_dominio("wwwejemplo.com")[0] == "wwwejemplo.com"


def test_avisa_que_le_saco_para_no_guardar_algo_distinto_en_silencio():
    _limpio, avisos = normalizar_dominio("https://www.ejemplo.com/seccion")

    assert any("http" in a for a in avisos)
    assert any("www." in a for a in avisos)
    # el aviso del camino explica POR QUÉ, que es lo que importa: no es una
    # simplificación, es que en HTTPS el camino va cifrado
    assert any("HTTPS" in a and "dominio" in a for a in avisos)


def test_sin_nada_para_sacar_no_inventa_avisos():
    limpio, avisos = normalizar_dominio("ejemplo.com")

    assert limpio == "ejemplo.com"
    assert avisos == []


def test_la_basura_sigue_sin_pasar():
    for basura in ("no es un dominio", "://", "...", "", "   ", "%%%"):
        limpio, _avisos = normalizar_dominio(basura)
        assert not is_valid_domain(limpio), basura


def test_la_regla_guardada_cubre_las_dos_formas(tmp_path):
    """Guardar sin www. no es solo cosmético: hace que la regla valga para
    www.ejemplo.com y para ejemplo.com."""
    archivo = tmp_path / "bl.txt"
    archivo.write_text("", encoding="utf-8")
    lista = Blocklist(str(archivo))

    limpio, _ = normalizar_dominio("https://www.ejemplo.com/x")
    lista.add_and_reload(limpio)

    assert lista.is_blocked("ejemplo.com") is True
    assert lista.is_blocked("www.ejemplo.com") is True
    assert lista.is_blocked("cdn.ejemplo.com") is True


# ---------------- limpiar una lista que ya existía ----------------


def test_normalizar_archivo_arregla_una_lista_vieja(tmp_path):
    archivo = tmp_path / "bl.txt"
    archivo.write_text(
        "# mis dominios\n"
        "https://www.google-analytics.com/\n"
        "ejemplo.com\n"
        "www.ejemplo.com\n"          # duplicado que aparece recién al limpiar
        "http://otro.com/seccion\n",
        encoding="utf-8",
    )
    lista = Blocklist(str(archivo))

    cambios = lista.normalizar_archivo()

    assert cambios == 3
    assert lista.manual_entries() == ["ejemplo.com", "google-analytics.com", "otro.com"]
    assert "# mis dominios" in archivo.read_text(encoding="utf-8")


def test_normalizar_archivo_no_toca_una_lista_que_ya_esta_limpia(tmp_path):
    archivo = tmp_path / "bl.txt"
    contenido = "# nada que hacer\nejemplo.com\notro.com\n"
    archivo.write_text(contenido, encoding="utf-8")

    assert Blocklist(str(archivo)).normalizar_archivo() == 0
    assert archivo.read_text(encoding="utf-8") == contenido


def test_normalizar_archivo_solo_toca_la_lista_manual(tmp_path):
    """paths[1] en adelante son archivos generados por feeds: no se tocan."""
    manual = tmp_path / "manual.txt"
    feeds = tmp_path / "feeds.txt"
    manual.write_text("www.uno.com\n", encoding="utf-8")
    feeds.write_text("www.dos.com\n", encoding="utf-8")
    lista = Blocklist([str(manual), str(feeds)])

    lista.normalizar_archivo()

    assert manual.read_text(encoding="utf-8").strip() == "uno.com"
    assert feeds.read_text(encoding="utf-8").strip() == "www.dos.com"


# ---------------- limpiar al mostrar ----------------


def test_limpiar_para_mostrar_solo_saca_el_www():
    assert limpiar_para_mostrar("www.google-analytics.com") == "google-analytics.com"
    assert limpiar_para_mostrar("download.windowsupdate.com") == "download.windowsupdate.com"
    assert limpiar_para_mostrar("wwwx.com") == "wwwx.com"
    assert limpiar_para_mostrar("") == ""


# ---------------- el panel ----------------


@pytest.fixture()
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("malicioso.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    logger = LoggerDB(str(tmp_path / "l.db"))
    logger.log_request("127.0.0.1", "CONNECT", "www.google-analytics.com", 443, "/", True,
                       reason="dominio en blocklist: www.google-analytics.com")
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", engine, logger
    finally:
        server.shutdown()


def test_el_historial_muestra_el_dominio_limpio_pero_el_detalle_el_real(panel):
    base, _engine, _logger = panel

    _status, body = pedir(base + "/")

    historial = body.split('id="historial"')[1].split("</tbody>")[0]
    # la celda visible va sin www., con el host completo en el title
    assert ">google-analytics.com</td>" in historial
    assert "title='www.google-analytics.com'" in historial
    # y el detalle conserva el host tal cual se conectó
    assert "www.google-analytics.com" in historial


def test_el_boton_permitir_manda_el_host_real_no_el_recortado(panel):
    """Si mandara el recortado, permitirías más de lo que viste."""
    base, _engine, _logger = panel

    _status, body = pedir(base + "/")

    assert "/allow?domain=www.google-analytics.com" in body


def test_investigar_lleva_a_la_pestana_consultar(panel):
    """Antes el clic solo te subía al principio de la página, sin mostrar
    nada. Ahora abre Consultar con el resultado ya calculado."""
    base, _engine, _logger = panel

    _status, body = pedir(base + "/osint?osint=malicioso.test")

    assert "Resultado para malicioso.test" in body
    assert "SE BLOQUEA" in body
    # y el JS abre esa pestaña cuando la URL trae la consulta
    assert "[?&]osint=" in body
    assert "abrir('osint')" in body


def test_el_formulario_de_consultar_manda_el_parametro_que_el_servidor_lee(panel):
    """Estaba roto: el formulario mandaba `q` y el servidor leía `osint`, así
    que consultar a mano no hacía nada (y encima `q` filtraba el historial)."""
    base, _engine, _logger = panel

    _status, body = pedir(base + "/")

    formulario = body.split("action='/osint'")[1].split("</form>")[0]
    assert "name='osint'" in formulario


def test_consultar_acepta_una_url_pegada(panel):
    base, _engine, _logger = panel

    _status, body = pedir(base + "/osint?osint=https%3A%2F%2Fwww.malicioso.test%2Fx")

    assert "Resultado para malicioso.test" in body
    assert "SE BLOQUEA" in body


def test_agregar_desde_el_panel_limpia_y_avisa(panel):
    base, engine, _logger = panel

    _status, body = pedir(base + "/blockdomain?domain=https%3A%2F%2Fwww.nuevo.com%2Fseccion")

    assert "nuevo.com" in engine.blocklist.manual_entries()
    assert "www.nuevo.com" not in engine.blocklist.manual_entries()
    assert "Se guardó como" in body


def test_la_lista_del_panel_se_ve_limpia(panel):
    base, engine, _logger = panel
    engine.blocklist.add_and_reload("www.viejo.com")  # entrada vieja, sin limpiar

    _status, body = pedir(base + "/")

    negra = body.split('id="tab-negra"')[1].split("</div>")[0]
    assert ">viejo.com</td>" in negra


# ---------------- acciones desde Consultar ----------------


@pytest.fixture()
def panel_con_vista(tmp_path):
    from secureproxy.view_prefs import PreferenciasDeVista

    (tmp_path / "bl.txt").write_text("malicioso.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    (tmp_path / "ruido.txt").write_text("# de fábrica\nwindowsupdate.com\n", encoding="utf-8")
    engine = FilterEngine(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        abuseipdb_client=AbuseIPDBClient("", 60),
        tor_list=TorExitNodeList(),
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    vista = PreferenciasDeVista(Blocklist(str(tmp_path / "ruido.txt")), ocultar_ruido=True)
    logger = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(5):
        logger.log_request("127.0.0.1", "CONNECT", "desktop.docker.com", 443, "/", False)
    logger.log_request("127.0.0.1", "CONNECT", "otro.test", 443, "/", False)
    server = build_dashboard_server(
        "127.0.0.1", 0, engine, logger, TelegramNotifier(False, "", ""),
        FirewallManager(False), engine.allowlist, vista=vista,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", engine, logger, vista
    finally:
        server.shutdown()


def test_consultar_ofrece_las_tres_acciones(panel_con_vista):
    """Investigar terminaba en un callejón sin salida: el panel te decía
    'se permite' y te dejaba sin nada para hacer."""
    base, _engine, _logger, _vista = panel_con_vista

    _status, body = pedir(base + "/osint?osint=desktop.docker.com")

    acciones = body.split("acciones-barra acciones-osint")[1].split("</div>")[0]
    assert "Bloquear siempre" in acciones
    assert "Permitir siempre" in acciones
    assert "Ocultar del panel" in acciones


def test_las_acciones_reflejan_el_estado_actual(panel_con_vista):
    base, _engine, _logger, _vista = panel_con_vista

    _status, body = pedir(base + "/osint?osint=malicioso.test")

    # Se acota a la barra de botones: los textos de confirmación viven
    # ahora en el bloque de JavaScript, al final de la página.
    acciones = body.split("acciones-barra acciones-osint")[1].split("</div>")[0]
    # ya está en la lista negra: se ofrece sacarlo, no volver a ponerlo
    assert "Sacar de la lista negra" in acciones
    assert "Bloquear siempre" not in acciones


def test_para_una_ip_no_se_ofrecen_acciones_de_dominio(panel_con_vista):
    """Las listas son por dominio: ofrecer un botón que no haría lo que dice
    sería peor que no ofrecerlo."""
    base, _engine, _logger, _vista = panel_con_vista

    _status, body = pedir(base + "/osint?osint=8.8.8.8")

    assert "Resultado para 8.8.8.8" in body
    assert "Qué hacer con esto" not in body


def test_ocultar_desde_el_panel_saca_el_dominio_del_top(panel_con_vista):
    """El caso real: `desktop.docker.com` se come el primer puesto del Top 10
    y no va a estar nunca en una lista genérica de telemetría."""
    base, _engine, logger, vista = panel_con_vista
    assert "desktop.docker.com" in dict(logger.top_hosts(limit=10, ocultar=True))

    _status, body = pedir(base + "/ocultar?domain=desktop.docker.com")

    assert vista.es_ruidoso("desktop.docker.com") is True
    assert "desktop.docker.com" not in dict(logger.top_hosts(limit=10, ocultar=True))
    assert "ya no se muestra en el panel" in body


def test_ocultar_no_cambia_lo_que_se_bloquea(panel_con_vista):
    base, engine, _logger, _vista = panel_con_vista

    pedir(base + "/ocultar?domain=malicioso.test")

    assert engine.evaluate("malicioso.test").blocked is True


def test_se_puede_volver_a_mostrar(panel_con_vista):
    base, _engine, logger, vista = panel_con_vista
    pedir(base + "/ocultar?domain=desktop.docker.com")

    _status, body = pedir(base + "/mostrar?domain=desktop.docker.com")

    assert vista.es_ruidoso("desktop.docker.com") is False
    assert "desktop.docker.com" in dict(logger.top_hosts(limit=10, ocultar=True))
    assert "vuelve a mostrarse" in body


def test_ocultar_acepta_una_url_pegada(panel_con_vista):
    base, _engine, _logger, vista = panel_con_vista

    pedir(base + "/ocultar?domain=https%3A%2F%2Fwww.desktop.docker.com%2Fx")

    assert vista.es_ruidoso("desktop.docker.com") is True


def test_el_historial_se_remarca_al_toque_no_al_rato(panel_con_vista):
    """Si no se remarcara, el dominio seguiría apareciendo hasta que pase
    tráfico nuevo, y parecería que el botón no hizo nada."""
    base, _engine, logger, _vista = panel_con_vista

    pedir(base + "/ocultar?domain=desktop.docker.com")

    assert logger.stats(ocultar=True)["ocultas"] == 5


def test_el_top_de_destinos_lleva_a_consultar(panel_con_vista):
    """Es donde uno mira cuando quiere saber qué es un destino."""
    base, _engine, _logger, _vista = panel_con_vista

    _status, body = pedir(base + "/")

    stats = body.split('id="estadisticas"')[1]
    assert "/osint?osint=desktop.docker.com" in stats


def test_la_lista_de_ruido_se_ve_y_se_edita_desde_configuracion(panel_con_vista):
    """Ocultar cosas sin poder ver qué ocultaste sería la mitad mala de
    esta funcionalidad."""
    base, _engine, _logger, _vista = panel_con_vista

    _status, body = pedir(base + "/")

    config = body.split('id="tab-config"')[1]
    assert "Dominios que se están ocultando" in config
    assert "windowsupdate.com" in config
    assert "/mostrar?domain=windowsupdate.com" in config
