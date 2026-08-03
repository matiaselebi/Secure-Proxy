"""Tests del circuit breaker de AbuseIPDBClient: si la API falla varias
veces seguidas, el cliente deja de intentar llamarla por un rato (fail-open
inmediato) en vez de pagar el timeout completo en cada request del proxy."""

import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy import http_client  # noqa: E402
from secureproxy.threat_intel import AbuseIPDBClient  # noqa: E402


class _FailingSession:
    """Simula requests.get fallando siempre con un error de red."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise requests.ConnectionError("upstream caído (simulado)")


def test_circuit_opens_after_threshold_consecutive_failures(monkeypatch):
    failing_get = _FailingSession()
    monkeypatch.setattr(http_client, "get", failing_get)
    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=0)

    for _ in range(AbuseIPDBClient.FAILURE_THRESHOLD):
        assert client.get_abuse_score(f"1.2.3.{_}") == 0

    assert client.circuit_open is True


def test_circuit_open_skips_network_call_entirely(monkeypatch):
    failing_get = _FailingSession()
    monkeypatch.setattr(http_client, "get", failing_get)
    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=0)

    for _ in range(AbuseIPDBClient.FAILURE_THRESHOLD):
        client.get_abuse_score(f"9.9.9.{_}")

    calls_before = failing_get.calls
    score = client.get_abuse_score("5.5.5.5")

    # No debe haber intentado la llamada de red: el circuito está abierto.
    assert failing_get.calls == calls_before
    assert score == 0


def test_circuit_closes_after_reset_timeout_and_successful_probe(monkeypatch):
    failing_get = _FailingSession()
    monkeypatch.setattr(http_client, "get", failing_get)
    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=0)

    for _ in range(AbuseIPDBClient.FAILURE_THRESHOLD):
        client.get_abuse_score(f"1.1.1.{_}")
    assert client.circuit_open is True

    # Simulamos que ya pasó el tiempo de enfriamiento retrocediendo la marca
    # de apertura, en vez de dormir el test de verdad.
    client._circuit_opened_at = time.time() - AbuseIPDBClient.RESET_TIMEOUT_SECONDS - 1
    assert client.circuit_open is False

    class _OkResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"abuseConfidenceScore": 17}}

    monkeypatch.setattr(http_client, "get", lambda *a, **k: _OkResponse())

    score = client.get_abuse_score("8.8.8.8")

    assert score == 17
    assert client.circuit_open is False
    assert client._consecutive_failures == 0


def test_single_transient_failure_does_not_open_circuit(monkeypatch):
    """Un fallo aislado no debe activar el circuit breaker: solo una racha
    de FAILURE_THRESHOLD fallos consecutivos lo abre."""
    failing_get = _FailingSession()
    monkeypatch.setattr(http_client, "get", failing_get)
    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=0)

    assert AbuseIPDBClient.FAILURE_THRESHOLD > 1
    client.get_abuse_score("2.2.2.2")

    assert client.circuit_open is False
