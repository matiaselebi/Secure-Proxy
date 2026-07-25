import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import update_blocklist  # noqa: E402


class FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        pass


def test_fetch_urlhaus_domains_parses_hostfile(monkeypatch):
    fake_text = "\n".join(
        [
            "# comentario, se ignora",
            "0.0.0.0 malicious-domain-1.com",
            "0.0.0.0 malicious-domain-2.com",
            "",
        ]
    )
    monkeypatch.setattr(
        update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text)
    )

    domains = update_blocklist.fetch_urlhaus_domains()

    assert domains == {"malicious-domain-1.com", "malicious-domain-2.com"}


def test_fetch_openphish_domains_extracts_hostname(monkeypatch):
    fake_text = "\n".join(
        [
            "http://phishing-site.example/login/paypal",
            "https://another-phish.example/wp-admin/secure",
            "",
        ]
    )
    monkeypatch.setattr(
        update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text)
    )

    domains = update_blocklist.fetch_openphish_domains()

    assert domains == {"phishing-site.example", "another-phish.example"}


def test_fetch_feodotracker_ips_parses_list(monkeypatch):
    fake_text = "\n".join(
        [
            "# Feodo Tracker IP Blocklist",
            "# Last updated: hoy",
            "1.2.3.4",
            "5.6.7.8",
            "",
        ]
    )
    monkeypatch.setattr(
        update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text)
    )

    ips = update_blocklist.fetch_feodotracker_ips()

    assert ips == {"1.2.3.4", "5.6.7.8"}


def test_is_stale_when_file_missing(tmp_path):
    path = tmp_path / "no-existe.txt"
    assert update_blocklist.is_stale(path, min_interval_hours=6) is True


def test_is_stale_respects_interval(tmp_path):
    path = tmp_path / "blocklist_feeds.txt"
    path.write_text("example.com\n")

    # Archivo recién escrito: no debería estar "stale" para un intervalo de 6hs.
    assert update_blocklist.is_stale(path, min_interval_hours=6) is False

    # Forzamos que parezca escrito hace 10 horas.
    ten_hours_ago = time.time() - (10 * 3600)
    os.utime(path, (ten_hours_ago, ten_hours_ago))

    assert update_blocklist.is_stale(path, min_interval_hours=6) is True
