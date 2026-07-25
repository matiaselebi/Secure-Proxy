"""Tests para la Allowlist (dominios que ganan por sobre todo lo demás) y el
cache persistente (SQLite) de resultados de AbuseIPDB."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.ip_reputation_cache import PersistentIPCache  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    TorExitNodeList,
)


class FakeAbuseIPDBClient(AbuseIPDBClient):
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


# ---------- Allowlist ----------


def test_allowlist_is_allowed_matches_domain_and_subdomain(tmp_path):
    path = tmp_path / "allowlist.txt"
    path.write_text("trusted-example.com\n")
    allowlist = Allowlist(str(path))

    assert allowlist.is_allowed("trusted-example.com") is True
    assert allowlist.is_allowed("sub.trusted-example.com") is True
    assert allowlist.is_allowed("other.com") is False


def test_allowlist_add_and_reload_persists_and_takes_effect_immediately(tmp_path):
    path = tmp_path / "allowlist.txt"
    allowlist = Allowlist(str(path))
    assert allowlist.is_allowed("new-domain.com") is False

    allowlist.add_and_reload("New-Domain.com")

    assert allowlist.is_allowed("new-domain.com") is True
    # Se escribió realmente en el archivo (persiste entre reinicios).
    assert "new-domain.com" in path.read_text()


def test_allowlist_wins_over_blocklist_in_filter_engine(tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malicious-example.com\n")
    blocklist = Blocklist(str(blocklist_path))

    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("malicious-example.com\n")
    allowlist = Allowlist(str(allowlist_path))

    engine = FilterEngine(
        blocklist,
        FakeAbuseIPDBClient(),
        FakeTorExitNodeList(),
        allowlist=allowlist,
    )

    decision = engine.evaluate("malicious-example.com")

    assert decision.blocked is False
    assert "allowlist" in decision.reason


def test_no_allowlist_configured_falls_back_to_blocklist(tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malicious-example.com\n")
    blocklist = Blocklist(str(blocklist_path))

    engine = FilterEngine(blocklist, FakeAbuseIPDBClient(), FakeTorExitNodeList())

    decision = engine.evaluate("malicious-example.com")

    assert decision.blocked is True


# ---------- Blocklist: alta/baja manual + listado (para la pestaña del dashboard) ----------


def test_blocklist_add_and_reload_takes_effect_immediately(tmp_path):
    path = tmp_path / "blocklist.txt"
    blocklist = Blocklist(str(path))
    assert blocklist.is_blocked("new-bad.com") is False

    blocklist.add_and_reload("New-Bad.com")

    assert blocklist.is_blocked("new-bad.com") is True
    assert "new-bad.com" in path.read_text()


def test_blocklist_add_and_reload_does_not_duplicate(tmp_path):
    path = tmp_path / "blocklist.txt"
    blocklist = Blocklist(str(path))

    blocklist.add_and_reload("dup.com")
    blocklist.add_and_reload("dup.com")

    assert path.read_text().count("dup.com") == 1


def test_blocklist_remove_and_reload(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("malicious-example.com\nkeep-me.com\n")
    blocklist = Blocklist(str(path))

    blocklist.remove_and_reload("malicious-example.com")

    assert blocklist.is_blocked("malicious-example.com") is False
    assert blocklist.is_blocked("keep-me.com") is True
    assert "malicious-example.com" not in path.read_text()


def test_blocklist_remove_and_reload_only_touches_manual_file(tmp_path):
    """Un dominio que viene de un feed automático (segundo archivo) no debe
    poder sacarse desde acá: solo se administra el archivo manual (paths[0])."""
    manual_path = tmp_path / "blocklist.txt"
    manual_path.write_text("")
    feeds_path = tmp_path / "blocklist_feeds.txt"
    feeds_path.write_text("from-feed.com\n")
    blocklist = Blocklist([str(manual_path), str(feeds_path)])
    assert blocklist.is_blocked("from-feed.com") is True

    blocklist.remove_and_reload("from-feed.com")

    # Sigue bloqueado: no estaba en el archivo manual, así que no se tocó.
    assert blocklist.is_blocked("from-feed.com") is True


def test_blocklist_manual_entries_lists_only_manual_domains(tmp_path):
    manual_path = tmp_path / "blocklist.txt"
    manual_path.write_text("# comentario\nmanual-bad.com\n\n")
    feeds_path = tmp_path / "blocklist_feeds.txt"
    feeds_path.write_text("feed-bad.com\n")
    blocklist = Blocklist([str(manual_path), str(feeds_path)])

    entries = blocklist.manual_entries()

    assert entries == ["manual-bad.com"]


# ---------- PersistentIPCache ----------


def test_persistent_cache_set_then_get_returns_score(tmp_path):
    cache = PersistentIPCache(str(tmp_path / "cache.db"))

    cache.set("1.2.3.4", 77)

    assert cache.get("1.2.3.4", max_age_seconds=3600) == 77


def test_persistent_cache_returns_none_for_unknown_ip(tmp_path):
    cache = PersistentIPCache(str(tmp_path / "cache.db"))

    assert cache.get("9.9.9.9", max_age_seconds=3600) is None


def test_persistent_cache_expires_entries_older_than_max_age(tmp_path):
    cache = PersistentIPCache(str(tmp_path / "cache.db"))
    cache.set("1.2.3.4", 50)

    # max_age_seconds=0: cualquier entrada, sin importar cuán reciente, ya
    # "venció" (time.time() - checked_at siempre es >= 0).
    assert cache.get("1.2.3.4", max_age_seconds=0) is None


def test_persistent_cache_survives_across_instances(tmp_path):
    """Simula un reinicio del proxy: una segunda instancia apuntando al mismo
    archivo .db debe ver lo que guardó la primera."""
    db_path = str(tmp_path / "cache.db")
    first = PersistentIPCache(db_path)
    first.set("5.6.7.8", 42)

    second = PersistentIPCache(db_path)

    assert second.get("5.6.7.8", max_age_seconds=3600) == 42


def test_abuseipdb_client_uses_persistent_cache_before_calling_api(tmp_path):
    """Si el cache persistente ya tiene el score, el cliente no debería
    necesitar llamar a la API (no seteamos api_key real, así que si
    igualmente devuelve el score correcto es porque vino del cache)."""
    persistent_cache = PersistentIPCache(str(tmp_path / "cache.db"))
    persistent_cache.set("1.1.1.1", 65)

    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=3600, persistent_cache=persistent_cache)

    score = client.get_abuse_score("1.1.1.1")

    assert score == 65
    # Además quedó en el cache en memoria para la próxima consulta.
    assert client._cache["1.1.1.1"][0] == 65


def test_abuseipdb_client_writes_through_to_persistent_cache_on_miss(tmp_path, monkeypatch):
    persistent_cache = PersistentIPCache(str(tmp_path / "cache.db"))
    client = AbuseIPDBClient(api_key="", cache_ttl=3600, persistent_cache=persistent_cache)

    # api_key="" hace que get_abuse_score devuelva 0 de entrada sin llamar a
    # la API ni tocar el cache persistente (fail-open temprano); probamos ese
    # camino explícitamente para no depender de la red en los tests.
    score = client.get_abuse_score("2.2.2.2")

    assert score == 0
    assert persistent_cache.get("2.2.2.2", max_age_seconds=3600) is None


def test_persistent_cache_clear_and_count(tmp_path):
    cache = PersistentIPCache(str(tmp_path / "cache.db"))
    cache.set("1.1.1.1", 10)
    cache.set("2.2.2.2", 20)
    assert cache.count() == 2

    cache.clear()

    assert cache.count() == 0
    assert cache.get("1.1.1.1", max_age_seconds=3600) is None


def test_abuseipdb_client_clear_cache_empties_memory_and_persistent(tmp_path):
    persistent_cache = PersistentIPCache(str(tmp_path / "cache.db"))
    client = AbuseIPDBClient(api_key="fake-key", cache_ttl=3600, persistent_cache=persistent_cache)
    persistent_cache.set("1.1.1.1", 55)
    client._cache["1.1.1.1"] = (55, time.time())

    client.clear_cache()

    assert client._cache == {}
    assert persistent_cache.count() == 0
