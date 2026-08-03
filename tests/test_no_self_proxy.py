"""Tests del bug más serio que tuvo el proyecto: el proxy proxeándose a sí mismo.

Qué pasó en una PC real, en dos días de uso:

  1.644.074 conexiones registradas a check.torproject.org -el 99,8% de todo
  el log-, la base de datos en 168 MB y el dashboard imposible de abrir.

La cadena era esta:

  a) `requests`, por defecto, respeta el proxy del sistema (en Windows lo
     lee del registro). El proxy del sistema es SecureProxy. Entonces cuando
     SecureProxy bajaba la lista de nodos TOR, el pedido volvía a entrar por
     SecureProxy.
  b) Ese pedido se evalúa como cualquier otro; evaluarlo consulta la lista
     de TOR; la lista no está todavía, así que se dispara otra descarga...
     que vuelve a entrar por el proxy. Bucle.
  c) Y encima, cuando la descarga fallaba, el código no registraba el
     intento: la marca de tiempo solo se actualizaba en caso de éxito. O
     sea que el "cachear por 6 horas" no aplicaba nunca y CADA conexión
     evaluada disparaba una descarga nueva.

Son dos bugs distintos que se potenciaban. Estos tests cubren los dos por
separado, porque arreglar uno solo dejaba el otro latente.
"""

import sys
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import http_client, notifier  # noqa: E402
from secureproxy.threat_intel import AbuseIPDBClient, TorExitNodeList  # noqa: E402


class _RespuestaOK:
    status_code = 200
    text = "1.1.1.1\n2.2.2.2\n"

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": {"abuseConfidenceScore": 0}}


# ---------- 1) nada de lo que sale del proxy pasa por el proxy ----------


def test_la_sesion_compartida_ignora_el_proxy_del_sistema():
    """`trust_env=False` es lo que impide que `requests` lea la config de
    proxy de Windows y termine mandándole el pedido a SecureProxy."""
    sesion = http_client.session()

    assert sesion.trust_env is False
    assert sesion.proxies == {"http": None, "https": None}


def test_get_y_post_fuerzan_proxy_nulo(monkeypatch):
    """Cinturón y tiradores: además de trust_env, cada llamada manda
    `proxies` explícito, por si algo intentara inyectar uno."""
    vistos = {}

    def fake(self, url, **kwargs):
        vistos[url] = kwargs.get("proxies")
        return _RespuestaOK()

    monkeypatch.setattr(requests.Session, "get", fake)
    monkeypatch.setattr(requests.Session, "post", fake)

    http_client.get("https://ejemplo.test/lista")
    http_client.post("https://ejemplo.test/alerta")

    assert vistos["https://ejemplo.test/lista"] == {"http": None, "https": None}
    assert vistos["https://ejemplo.test/alerta"] == {"http": None, "https": None}


@pytest.mark.parametrize(
    "modulo, atributo",
    [
        ("secureproxy.threat_intel", "http_client"),
        ("secureproxy.notifier", "http_client"),
    ],
)
def test_los_modulos_que_salen_a_internet_usan_el_cliente_seguro(modulo, atributo):
    import importlib

    assert hasattr(importlib.import_module(modulo), atributo), (
        f"{modulo} tiene que salir por http_client, no por requests directo: "
        "si no, sus pedidos vuelven a entrar por el propio proxy"
    )


def test_la_lista_de_tor_se_baja_sin_pasar_por_el_proxy(monkeypatch):
    llamadas = []

    def fake_get(url, **kwargs):
        llamadas.append((url, kwargs.get("proxies")))
        return _RespuestaOK()

    monkeypatch.setattr(http_client, "get", fake_get)
    TorExitNodeList(cache_ttl=3600).is_tor_exit_node("9.9.9.9")

    assert llamadas, "tendría que haber bajado la lista"
    url, _proxies = llamadas[0]
    assert "torproject" in url


def test_abuseipdb_se_consulta_sin_pasar_por_el_proxy(monkeypatch):
    llamadas = []
    monkeypatch.setattr(
        http_client, "get", lambda url, **kw: (llamadas.append(url), _RespuestaOK())[1]
    )

    AbuseIPDBClient(api_key="fake", cache_ttl=0).get_abuse_score("8.8.8.8")

    assert llamadas and "abuseipdb" in llamadas[0]


def test_telegram_alerta_sin_pasar_por_el_proxy(monkeypatch):
    """Si la alerta saliera por el proxy, cada bloqueo generaría tráfico
    nuevo hacia el propio proxy... que podría bloquearse y alertar de nuevo."""
    llamadas = []
    monkeypatch.setattr(
        notifier.http_client, "post", lambda url, **kw: llamadas.append(url)
    )

    notifier.TelegramNotifier(True, "token", "chat").send_alert("hola")

    assert llamadas and "telegram" in llamadas[0]


# ---------- 2) una descarga que falla no se reintenta en cada conexión ----------


def test_una_descarga_fallida_no_se_reintenta_en_cada_conexion(monkeypatch):
    """El bug exacto: `_last_fetch` solo se actualizaba en caso de éxito, así
    que con la descarga caída cada conexión evaluada largaba una descarga
    nueva. Con tráfico normal eso son miles de pedidos por minuto."""
    intentos = []

    def siempre_falla(url, **kwargs):
        intentos.append(url)
        raise requests.ConnectionError("sin red (simulado)")

    monkeypatch.setattr(http_client, "get", siempre_falla)
    tor = TorExitNodeList(cache_ttl=3600)

    for _ in range(50):
        tor.is_tor_exit_node("1.2.3.4")

    assert len(intentos) == 1, (
        f"reintentó {len(intentos)} veces en 50 conexiones; tiene que esperar "
        "antes de volver a probar"
    )


def test_pasado_el_enfriamiento_vuelve_a_intentar(monkeypatch):
    """Tampoco puede quedarse apagado para siempre: si la red vuelve, la
    detección de TOR tiene que revivir sola."""
    intentos = []

    def siempre_falla(url, **kwargs):
        intentos.append(url)
        raise requests.ConnectionError("sin red (simulado)")

    monkeypatch.setattr(http_client, "get", siempre_falla)
    tor = TorExitNodeList(cache_ttl=3600)
    tor.is_tor_exit_node("1.2.3.4")
    assert len(intentos) == 1

    # Simula que pasó el tiempo de enfriamiento.
    tor._last_attempt -= tor.RETRY_AFTER_FAILURE_SECONDS + 1
    tor.is_tor_exit_node("1.2.3.4")

    assert len(intentos) == 2


def test_una_descarga_exitosa_se_cachea_por_el_ttl(monkeypatch):
    descargas = []
    monkeypatch.setattr(
        http_client, "get", lambda url, **kw: (descargas.append(url), _RespuestaOK())[1]
    )
    tor = TorExitNodeList(cache_ttl=3600)

    for _ in range(100):
        assert tor.is_tor_exit_node("1.1.1.1") is True

    assert len(descargas) == 1, "con la lista en memoria no se vuelve a bajar"
