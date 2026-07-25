import sys
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
