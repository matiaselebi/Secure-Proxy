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
    # Puerto propio del dashboard, separado del que proxea: el 8888 es el que
    # ponés en la configuración de Windows, el 8889 es la página. Queda en
    # línea con SecureDNS (8890) y SecureVPN (8891), un panel por puerto.
    dashboard_port: int = 8889


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
    # Pools de minería: lista propia para que el motivo del bloqueo diga
    # "cryptojacking" en vez de un genérico "dominio en blocklist".
    mining_pools_path: str = "data/mining_pools.txt"
    # Rangos de IP con mala reputación (FireHOL). Son CIDR, no IPs sueltas.
    ip_ranges_feeds_path: str = "data/ip_ranges_feeds.txt"
    # Modo lista blanca: todo dominio que no esté permitido se bloquea.
    # En una PC de uso diario rompe todo; se usa junto con mode="audit".
    block_unknown_domains: bool = False
    # Permitir salir hacia loopback, redes privadas y puertos que no son web.
    # Apagado a propósito: un proxy que tuneliza a cualquier destino y a
    # cualquier puerto es un canal TCP arbitrario hacia los servicios
    # internos de la máquina y de la LAN.
    allow_internal_destinations: bool = False
    # Atajo que fija varias opciones a la vez: normal, estricto o paranoico.
    security_level: str = "normal"
    check_tor_exit_nodes: bool = True
    tor_list_cache_ttl: int = 21600
    # "enforce" (default): bloquea de verdad. "audit": evalúa y registra qué
    # se hubiera bloqueado, pero deja pasar todo el tráfico. Útil para
    # probar una lista o umbral nuevo sin riesgo antes de aplicarlo en serio.
    mode: str = "enforce"


@dataclass
class LoggingConfig:
    db_path: str = "data/proxy_logs.db"
    # Tope de filas del historial. El proxy del sistema ve TODAS las
    # conexiones de la PC, así que sin tope el archivo crece para siempre
    # (llegó a 168 MB en dos días en una prueba real, dejando el dashboard
    # inservible). 0 desactiva el recorte.
    max_rows: int = 200_000
    # Base local de país/ASN por IP. Si no está, el proxy anda igual y esos
    # campos quedan vacíos. Se genera con scripts/update_geoip.py.
    geoip_db_path: str = "data/geoip.db"
    # Guardar qué proceso abrió cada conexión. Se resuelve contra la tabla de
    # sockets del sistema operativo, sin salir a la red y sin dependencias.
    identify_process: bool = True


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class AlertsConfig:
    """Avisos en el escritorio. Sin depender de ningún servicio externo."""

    enabled: bool = True
    # Solo los bloqueos que significan algo (C2, minería, reputación de IP,
    # TOR). Con `false` avisa de todos, incluidos los de la lista manual.
    only_severe: bool = True


@dataclass
class DashboardConfig:
    """Lo que se MUESTRA en el panel. Separado de `filtering` a propósito:
    nada de acá cambia qué se bloquea, solo qué tapa la vista."""

    # Saca del panel los dominios de telemetría, comprobación de conexión y
    # actualizaciones. Siguen registrados y contados; el panel dice cuántos
    # está ocultando y el buscador los encuentra igual.
    hide_noise: bool = True
    noisy_domains_path: str = "data/noisy_domains.txt"


@dataclass
class FirewallConfig:
    enabled: bool = False


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    filtering: FilteringConfig = field(default_factory=FilteringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
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
    dashboard_raw = raw.get("dashboard", {})
    alerts_raw = raw.get("alerts", {})
    telegram_raw = raw.get("telegram", {})
    firewall_raw = raw.get("firewall", {})

    cfg = Config(
        proxy=ProxyConfig(**proxy_raw),
        filtering=FilteringConfig(**filtering_raw),
        logging=LoggingConfig(**logging_raw),
        dashboard=DashboardConfig(**dashboard_raw),
        alerts=AlertsConfig(**alerts_raw),
        telegram=TelegramConfig(
            enabled=telegram_raw.get("enabled", False),
            bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
            chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        ),
        firewall=FirewallConfig(**firewall_raw),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
    )
    return cfg
