"""Carga la configuración desde config/config.yaml y variables de entorno (.env)."""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8888
    max_threads: int = 50


@dataclass
class FilteringConfig:
    blocklist_path: str = "data/blocklist.txt"
    # Generados automáticamente por scripts/update_blocklist.py (URLhaus + OpenPhish + Feodo Tracker).
    # Si los archivos todavía no existen (no corriste el script nunca), simplemente se ignoran.
    feeds_blocklist_path: str = "data/blocklist_feeds.txt"
    ip_feeds_blocklist_path: str = "data/ip_blocklist_feeds.txt"
    # Lista blanca manual: gana por sobre cualquier otro chequeo. Se edita a
    # mano o vía el botón "Permitir" del dashboard.
    allowlist_path: str = "data/allowlist.txt"
    # Cada cuántas horas como mínimo se vuelve a descargar la lista automáticamente al arrancar.
    feeds_update_interval_hours: float = 6
    abuseipdb_min_score: int = 50
    abuseipdb_cache_ttl: int = 3600
    # Cache persistente (SQLite) de resultados de AbuseIPDB: sobrevive a
    # reinicios del proxy, para no volver a gastar cupo de la API (1000
    # consultas/día en el plan gratuito) por una IP ya consultada hace poco.
    abuseipdb_cache_db_path: str = "data/ip_reputation_cache.db"
    check_tor_exit_nodes: bool = True
    tor_list_cache_ttl: int = 21600


@dataclass
class LoggingConfig:
    db_path: str = "data/proxy_logs.db"


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class FirewallConfig:
    enabled: bool = False


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    filtering: FilteringConfig = field(default_factory=FilteringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    abuseipdb_api_key: str = ""

    def resolve_path(self, relative_path: str) -> Path:
        """Resuelve una ruta relativa al config.yaml contra la raíz del proyecto."""
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return PROJECT_ROOT / path


def load_config(config_path: str | None = None) -> Config:
    """Lee config.yaml y el .env, y arma un objeto Config tipado."""
    load_dotenv(PROJECT_ROOT / ".env")

    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "config.yaml")

    raw: dict = {}
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    proxy_raw = raw.get("proxy", {})
    filtering_raw = raw.get("filtering", {})
    logging_raw = raw.get("logging", {})
    telegram_raw = raw.get("telegram", {})
    firewall_raw = raw.get("firewall", {})

    cfg = Config(
        proxy=ProxyConfig(**proxy_raw),
        filtering=FilteringConfig(**filtering_raw),
        logging=LoggingConfig(**logging_raw),
        telegram=TelegramConfig(
            enabled=telegram_raw.get("enabled", False),
            bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
            chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        ),
        firewall=FirewallConfig(**firewall_raw),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
    )
    return cfg
