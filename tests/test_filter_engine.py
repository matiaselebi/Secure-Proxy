import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
)


class FakeAbuseIPDBClient(AbuseIPDBClient):
    """Evita llamadas reales a la API en los tests."""

    def __init__(self, score_by_ip=None):
        super().__init__(api_key="fake", cache_ttl=3600)
        self.score_by_ip = score_by_ip or {}

    def get_abuse_score(self, ip: str) -> int:
        return self.score_by_ip.get(ip, 0)


class FakeTorExitNodeList(TorExitNodeList):
    def __init__(self, tor_ips=None):
        super().__init__(cache_ttl=99999)
        self._tor_ips = tor_ips or set()

    def is_tor_exit_node(self, ip: str) -> bool:
        return ip in self._tor_ips


def make_blocklist(tmp_path, domains):
    path = tmp_path / "blocklist.txt"
    path.write_text("\n".join(domains))
    return Blocklist(str(path))


def test_blocklist_blocks_exact_domain(tmp_path):
    blocklist = make_blocklist(tmp_path, ["malicious-example.com"])
    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList())

    decision = engine.evaluate("malicious-example.com")

    assert decision.blocked is True
    assert "blocklist" in decision.reason


def test_blocklist_blocks_subdomain(tmp_path):
    blocklist = make_blocklist(tmp_path, ["malicious-example.com"])
    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList())

    decision = engine.evaluate("sub.malicious-example.com")

    assert decision.blocked is True


def test_allows_clean_domain(tmp_path, monkeypatch):
    blocklist = make_blocklist(tmp_path, ["malicious-example.com"])
    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList())

    monkeypatch.setattr(
        "secureproxy.filter_engine.resolve_host_to_ip", lambda host: "93.184.216.34"
    )

    decision = engine.evaluate("example.com")

    assert decision.blocked is False
    assert decision.resolved_ip == "93.184.216.34"


def test_blocks_high_abuse_score_ip(tmp_path, monkeypatch):
    blocklist = make_blocklist(tmp_path, [])
    abuse_client = FakeAbuseIPDBClient(score_by_ip={"1.2.3.4": 90})
    engine = FilterEngine(
        blocklist, abuse_client, FakeTorExitNodeList(), abuseipdb_min_score=50
    )

    monkeypatch.setattr(
        "secureproxy.filter_engine.resolve_host_to_ip", lambda host: "1.2.3.4"
    )

    decision = engine.evaluate("suspicious-domain.com")

    assert decision.blocked is True
    assert "AbuseIPDB" in decision.reason


def test_blocks_tor_exit_node(tmp_path, monkeypatch):
    blocklist = make_blocklist(tmp_path, [])
    tor_list = FakeTorExitNodeList(tor_ips={"5.6.7.8"})
    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), tor_list)

    monkeypatch.setattr(
        "secureproxy.filter_engine.resolve_host_to_ip", lambda host: "5.6.7.8"
    )

    decision = engine.evaluate("tor-exit.example.com")

    assert decision.blocked is True
    assert "TOR" in decision.reason


def test_blocks_feodotracker_c2_ip(tmp_path, monkeypatch):
    blocklist = make_blocklist(tmp_path, [])

    ip_blocklist_path = tmp_path / "ip_blocklist_feeds.txt"
    ip_blocklist_path.write_text("9.9.9.9\n")
    ip_blocklist = IPBlocklist(str(ip_blocklist_path))

    engine = FilterEngine(
        blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList(), ip_blocklist=ip_blocklist
    )

    monkeypatch.setattr(
        "secureproxy.filter_engine.resolve_host_to_ip", lambda host: "9.9.9.9"
    )

    decision = engine.evaluate("c2-domain.example.com")

    assert decision.blocked is True
    assert "Feodo Tracker" in decision.reason


def test_audit_mode_does_not_block_but_flags_would_have_blocked(tmp_path):
    blocklist = make_blocklist(tmp_path, ["malicious-example.com"])
    engine = FilterEngine(
        blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList(), mode="audit"
    )

    decision = engine.evaluate("malicious-example.com")

    assert decision.blocked is False
    assert decision.would_have_blocked is True
    assert "AUDIT" in decision.reason
    assert "malicious-example.com" in decision.reason


def test_audit_mode_leaves_clean_domains_unaffected(tmp_path, monkeypatch):
    blocklist = make_blocklist(tmp_path, [])
    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList(), mode="audit")
    monkeypatch.setattr(
        "secureproxy.filter_engine.resolve_host_to_ip", lambda host: "1.2.3.4"
    )

    decision = engine.evaluate("clean-example.com")

    assert decision.blocked is False
    assert decision.would_have_blocked is False


def test_invalid_mode_raises():
    import pytest

    with pytest.raises(ValueError):
        FilterEngine(None, None, None, mode="not-a-real-mode")
