"""Fase 3 del punto 8: lo único que solo puede contestar este proxy.

Al proxy se le sacó todo lo que hacían otros. Lo que quedó tiene que ser lo
que ninguna otra pieza puede dar: el proceso que abrió la conexión, cuánto
transfirió, y con qué ritmo.

Los tests están escritos alrededor de la pregunta que importa: ¿esto
distingue a una persona navegando de un programa preguntando "¿hay órdenes?"
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import beaconing  # noqa: E402


def cada(segundos: float, cuantas: int, desde: float = 1_000_000.0,
          ruido: float = 0.0) -> list:
    """Marcas de tiempo a intervalo fijo, con un ruido opcional."""
    marcas, t = [], desde
    for i in range(cuantas):
        marcas.append(t)
        t += segundos + (ruido if i % 2 else -ruido)
    return marcas


# ------------------------------------------------------------ la cuenta

def test_un_ritmo_perfecto_se_detecta():
    """Un programa que consulta cada minuto: 60, 60, 60, 60..."""
    analisis = beaconing.evaluar(cada(60, 12))
    assert analisis["sospechoso"]
    assert analisis["coeficiente"] < 0.05
    assert "¿hay órdenes?" in analisis["motivo"]


def test_un_ritmo_con_ruido_de_red_igual_se_detecta():
    """La red nunca es perfecta. Un beacon real tiene un par de segundos de
    variación y sigue siendo obviamente un beacon."""
    assert beaconing.evaluar(cada(60, 12, ruido=3))["sospechoso"]


def test_una_persona_navegando_no_se_detecta():
    """Intervalos caóticos: 3 segundos, 47, 2, 300, 15..."""
    marcas, t = [], 1_000_000.0
    for salto in (3, 47, 2, 300, 15, 120, 8, 240, 33, 5, 90, 12):
        t += salto
        marcas.append(t)
    assert not beaconing.evaluar(marcas)["sospechoso"]


def test_el_coeficiente_no_depende_de_la_escala():
    """LA razón de usar coeficiente de variación y no un umbral de desvío.

    Un beacon de 60 segundos y uno de una hora, igual de regulares, tienen que
    dar lo mismo: el período lo elige el atacante. Con un umbral fijo sobre el
    desvío, 5 segundos de variación es muchísimo para un beacon de 10 segundos
    y nada para uno de una hora.
    """
    rapido = beaconing.evaluar(cada(60, 12, ruido=3))
    lento = beaconing.evaluar(cada(3600, 12, ruido=180))
    assert rapido["sospechoso"] and lento["sospechoso"]
    assert abs(rapido["coeficiente"] - lento["coeficiente"]) < 0.02


# --------------------------------------------------- cuándo NO se opina

def test_con_pocas_conexiones_no_se_opina():
    """Con tres intervalos cualquier cosa parece regular por casualidad."""
    analisis = beaconing.evaluar(cada(60, 3))
    assert not analisis["sospechoso"]
    assert "hacen falta al menos" in analisis["motivo"]


def test_dos_conexiones_no_son_un_ritmo():
    """Un solo intervalo es siempre "perfectamente regular"."""
    assert not beaconing.evaluar([1000.0, 1060.0])["sospechoso"]


def test_una_pagina_cargando_sus_recursos_no_es_un_beacon():
    """Veinte pedidos al mismo servidor en dos segundos es una página web."""
    analisis = beaconing.evaluar(cada(0.1, 20))
    assert not analisis["sospechoso"]
    assert "página cargando" in analisis["motivo"]


def test_intervalos_larguisimos_no_se_afirman():
    """Más de seis horas entre conexiones no es un ritmo que se pueda
    sostener con la ventana de historial que guarda este proxy."""
    analisis = beaconing.evaluar(cada(30000, 12))
    assert not analisis["sospechoso"]
    assert "demasiado largos" in analisis["motivo"]


def test_siempre_se_explica_por_que_no():
    """El motivo del "no" es lo que permite entender la pantalla en vez de
    confiar en ella."""
    for marcas in (cada(60, 3), cada(0.1, 20), cada(30000, 12)):
        assert beaconing.evaluar(marcas)["motivo"]


# --------------------------------------------------------- el agrupado

def test_se_agrupa_por_proceso_y_destino():
    """Dos programas hablando con el mismo servidor son DOS historias.
    Mezclarlos rompe justamente la regularidad que se está buscando: los
    intervalos entrelazados de dos beacons parecen caóticos.
    """
    filas = []
    for t in cada(60, 12):
        filas.append({"ts": t, "host": "malo.com", "proceso": "svchost.exe"})
    # El navegador habla con el mismo destino, pero cuando se le canta.
    for t in (1_000_010, 1_000_073, 1_000_075, 1_000_400):
        filas.append({"ts": t, "host": "malo.com", "proceso": "chrome.exe"})

    resultados = beaconing.analizar(filas)
    assert len(resultados) == 1
    assert resultados[0]["proceso"] == "svchost.exe"


def test_se_ordena_lo_mas_regular_primero():
    """Es lo que menos se parece a una persona."""
    filas = []
    for t in cada(60, 12):
        filas.append({"ts": t, "host": "perfecto.com", "proceso": "a.exe"})
    for t in cada(60, 12, ruido=10):
        filas.append({"ts": t, "host": "menos.com", "proceso": "b.exe"})
    resultados = beaconing.analizar(filas)
    assert [r["destino"] for r in resultados] == ["perfecto.com", "menos.com"]


def test_los_bytes_se_suman_por_grupo():
    filas = [{"ts": t, "host": "malo.com", "proceso": "x.exe",
              "bytes_out": 100, "bytes_in": 250} for t in cada(60, 12)]
    assert beaconing.analizar(filas)[0]["bytes"] == 12 * 350


def test_una_fila_sin_destino_no_rompe_nada():
    filas = [{"ts": t, "host": "", "proceso": "x"} for t in cada(60, 12)]
    assert beaconing.analizar(filas) == []


# ------------------------------------------------- lo que esto NO afirma

def test_el_resultado_dice_ritmo_y_no_malicioso():
    """Hay cosas legítimas con ritmo perfecto: un cliente de correo
    sincronizando, un chequeo de actualizaciones, la telemetría de una app.

    Por eso el resultado describe el RITMO y se muestra junto al proceso: el
    ritmo solo no alcanza, el ritmo más quién lo hace sí es una pregunta que
    se puede contestar mirando una pantalla.
    """
    motivo = beaconing.evaluar(cada(60, 12))["motivo"]
    assert "malicioso" not in motivo.lower()
    assert "virus" not in motivo.lower()
    assert "conexiones cada" in motivo


# ---------------------------------------------- de la base al análisis

def test_el_historial_sale_de_la_base_en_el_formato_que_espera(tmp_path):
    """De punta a punta: lo que guarda el proxy alimenta el análisis sin que
    nadie tenga que traducir nada a mano."""
    from secureproxy.logger_db import LoggerDB

    db = LoggerDB(str(tmp_path / "l.db"))
    for i in range(12):
        db.log_request(
            client_ip="127.0.0.1", method="CONNECT", host="malo.com", port=443,
            path="/", blocked=False, reason="", process="svchost.exe",
            bytes_out=100, bytes_in=200)

    filas = db.filas_para_beaconing()
    assert len(filas) == 12
    assert filas[0]["host"] == "malo.com"
    assert filas[0]["proceso"] == "svchost.exe"
    assert isinstance(filas[0]["ts"], float)


def test_solo_se_analiza_lo_que_paso_el_filtro(tmp_path):
    """Un destino bloqueado ya lo agarró una lista: no hace falta analizar el
    ritmo para saber que estaba mal. Lo que este proxy puede contestar y nadie
    más es qué pasa con lo que PASÓ el filtro."""
    from secureproxy.logger_db import LoggerDB

    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_request(client_ip="1", method="CONNECT", host="bloqueado.com",
                   port=443, path="/", blocked=True, reason="lista")
    db.log_request(client_ip="1", method="CONNECT", host="permitido.com",
                   port=443, path="/", blocked=False, reason="")

    hosts = {f["host"] for f in db.filas_para_beaconing()}
    assert hosts == {"permitido.com"}


# ------------------------------- la conclusión guardada, para SecureCenter

def _sembrar_ritmo(db, host, proceso, cuantas=12, cada_seg=60):
    from datetime import datetime, timedelta, timezone
    ahora = datetime.now(timezone.utc)
    with db._connect() as conn:
        for i in range(cuantas):
            conn.execute(
                "INSERT INTO requests (timestamp, client_ip, method, host, port, "
                "path, blocked, reason, duration_ms, process, noisy, bytes_out, "
                "bytes_in) VALUES (?,?,?,?,?,?,?,?,?,?,0,10,20)",
                ((ahora - timedelta(seconds=cada_seg * i)).isoformat(),
                 "127.0.0.1", "CONNECT", host, 443, "/", 0, "", 1.0, proceso))
        conn.commit()


def test_el_ritmo_queda_escrito_en_la_base(tmp_path):
    """No se calcula solo cuando alguien abre el panel: SecureCenter lee
    bases, no pantallas. Si la cuenta viviera en el panel, Detect tendría que
    repetirla, y repetir cuentas es justo lo que este punto vino a sacar."""
    from secureproxy.logger_db import LoggerDB

    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_ritmo(db, "c2.test", "rundll32.exe")

    assert db.actualizar_ritmos() == 1
    guardado = db.ritmos()[0]
    assert guardado["destino"] == "c2.test"
    assert guardado["proceso"] == "rundll32.exe"
    assert guardado["conexiones"] == 12
    assert guardado["bytes"] == 12 * 30
    assert guardado["motivo"]


def test_un_ritmo_que_dejo_de_estar_se_borra(tmp_path):
    """Lo importante del guardado es el borrado. Sin él, un destino que dejó
    de tener ritmo hace tres semanas seguiría generando incidentes: la
    conclusión quedaría congelada mientras el mundo cambió."""
    from secureproxy.logger_db import LoggerDB

    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_ritmo(db, "viejo.test", "x.exe")
    db.actualizar_ritmos()
    assert db.ritmos()

    with db._connect() as conn:
        conn.execute("DELETE FROM requests")
        conn.commit()

    assert db.actualizar_ritmos() == 0
    assert db.ritmos() == []


def test_el_ruido_conocido_no_se_guarda_como_ritmo(tmp_path):
    """La telemetría de Windows tiene un ritmo perfecto y no es un implante.
    Es EL falso positivo de esta detección, así que se filtra antes de
    guardar y no después, para que Detect nunca lo vea."""
    from secureproxy.logger_db import LoggerDB

    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_ritmo(db, "telemetria.test", "svchost.exe")
    with db._connect() as conn:
        conn.execute("UPDATE requests SET noisy = 1")
        conn.commit()

    assert db.actualizar_ritmos() == 0
