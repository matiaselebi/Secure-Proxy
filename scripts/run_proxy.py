#!/usr/bin/env python3
"""Punto de entrada: levanta el proxy con la configuración de config/config.yaml."""

import os
import sys
import threading
from pathlib import Path

# Permite correr este script directo (python scripts/run_proxy.py) sin instalar el paquete.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "proxy.pid"

import update_blocklist  # noqa: E402
from secureproxy.config_loader import load_config  # noqa: E402
from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_proxy_server  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
)


def _update_feeds_in_background(min_interval_hours: float, blocklist: Blocklist, ip_blocklist: IPBlocklist) -> None:
    """Corre en un hilo aparte para no demorar el arranque del proxy. Si
    efectivamente descarga algo nuevo, recarga las listas en caliente sin
    necesidad de reiniciar el proceso."""
    try:
        updated = update_blocklist.main(force=False, min_interval_hours=min_interval_hours)
        if updated:
            blocklist.reload()
            ip_blocklist.reload()
            print("[SecureProxy] listas de amenazas actualizadas y recargadas en caliente.")
    except Exception as exc:  # noqa: BLE001 - no debe tumbar el proxy por esto
        print(f"[SecureProxy] no se pudo actualizar la blocklist automática: {exc}")


def main() -> None:
    cfg = load_config()

    blocklist = Blocklist(
        [
            str(cfg.resolve_path(cfg.filtering.blocklist_path)),
            str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path)),
        ]
    )
    ip_blocklist = IPBlocklist(str(cfg.resolve_path(cfg.filtering.ip_feeds_blocklist_path)))
    abuseipdb_client = AbuseIPDBClient(cfg.abuseipdb_api_key, cfg.filtering.abuseipdb_cache_ttl)
    tor_list = TorExitNodeList(cfg.filtering.tor_list_cache_ttl)

    filter_engine = FilterEngine(
        blocklist=blocklist,
        abuseipdb_client=abuseipdb_client,
        tor_list=tor_list,
        ip_blocklist=ip_blocklist,
        abuseipdb_min_score=cfg.filtering.abuseipdb_min_score,
        check_tor_exit_nodes=cfg.filtering.check_tor_exit_nodes,
    )

    logger_db = LoggerDB(str(cfg.resolve_path(cfg.logging.db_path)))
    notifier = TelegramNotifier(cfg.telegram.enabled, cfg.telegram.bot_token, cfg.telegram.chat_id)
    firewall = FirewallManager(cfg.firewall.enabled)

    server = build_proxy_server(
        cfg.proxy.host, cfg.proxy.port, filter_engine, logger_db, notifier, firewall
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureProxy] escuchando en {cfg.proxy.host}:{cfg.proxy.port}")
    print(f"[SecureProxy] blocklist: {cfg.resolve_path(cfg.filtering.blocklist_path)}")
    print(f"[SecureProxy] logs: {cfg.resolve_path(cfg.logging.db_path)}")
    print(f"[SecureProxy] PID: {os.getpid()} (guardado en {PID_FILE})")
    print("[SecureProxy] Ctrl+C para detener (o 'python scripts/stop_proxy.py' si corre en segundo plano).")

    # Actualiza las listas de amenazas en un hilo aparte: el proxy ya empieza
    # a escuchar de inmediato, sin esperar a que termine la descarga.
    update_thread = threading.Thread(
        target=_update_feeds_in_background,
        args=(cfg.filtering.feeds_update_interval_hours, blocklist, ip_blocklist),
        daemon=True,
    )
    update_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SecureProxy] deteniendo...")
        server.shutdown()
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


if __name__ == "__main__":
    main()
