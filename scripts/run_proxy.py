#!/usr/bin/env python3
"""Punto de entrada: levanta el proxy con la configuración de config/config.yaml."""

import os
import sys
import threading
import time
from pathlib import Path

# Permite correr este script directo (python scripts/run_proxy.py) sin instalar el paquete.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "proxy.pid"

# Cada cuántos segundos se releen blocklist/allowlist/ip_blocklist desde
# disco mientras el proxy está corriendo. Es liviano (son archivos de texto
# chicos) y separado del ciclo pesado de descarga de feeds (6hs por
# defecto): así, un dominio agregado a mano (editando el .txt, desde el
# menú .bat, o por otro medio que no sea el propio dashboard) se aplica
# solo, sin tener que reiniciar el proceso.
LIGHT_RELOAD_INTERVAL_SECONDS = 15

import update_blocklist  # noqa: E402
from secureproxy.config_loader import load_config  # noqa: E402
from secureproxy.filter_engine import FilterEngine  # noqa: E402
from secureproxy.firewall_rules import FirewallManager  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.ip_reputation_cache import PersistentIPCache  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_proxy_server  # noqa: E402
from secureproxy.threat_intel import (  # noqa: E402
    AbuseIPDBClient,
    Allowlist,
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


def _light_reload_loop(blocklist: Blocklist, allowlist: Allowlist, ip_blocklist: IPBlocklist) -> None:
    """Vuelve a leer los archivos de listas cada pocos segundos, para que
    cualquier edición manual (menú .bat, editar el .txt a mano, etc.) se
    aplique sola sin reiniciar el proceso. No descarga nada de internet -
    eso lo sigue haciendo _update_feeds_in_background, por separado."""
    while True:
        time.sleep(LIGHT_RELOAD_INTERVAL_SECONDS)
        try:
            blocklist.reload()
            allowlist.reload()
            ip_blocklist.reload()
        except Exception as exc:  # noqa: BLE001 - no debe tumbar el proxy por esto
            print(f"[SecureProxy] error recargando listas: {exc}")


def main() -> None:
    cfg = load_config()

    blocklist = Blocklist(
        [
            str(cfg.resolve_path(cfg.filtering.blocklist_path)),
            str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path)),
        ]
    )
    ip_blocklist = IPBlocklist(str(cfg.resolve_path(cfg.filtering.ip_feeds_blocklist_path)))
    allowlist = Allowlist(str(cfg.resolve_path(cfg.filtering.allowlist_path)))
    persistent_ip_cache = PersistentIPCache(str(cfg.resolve_path(cfg.filtering.abuseipdb_cache_db_path)))
    abuseipdb_client = AbuseIPDBClient(
        cfg.abuseipdb_api_key,
        cfg.filtering.abuseipdb_cache_ttl,
        persistent_cache=persistent_ip_cache,
    )
    tor_list = TorExitNodeList(cfg.filtering.tor_list_cache_ttl)

    filter_engine = FilterEngine(
        blocklist=blocklist,
        abuseipdb_client=abuseipdb_client,
        tor_list=tor_list,
        ip_blocklist=ip_blocklist,
        allowlist=allowlist,
        abuseipdb_min_score=cfg.filtering.abuseipdb_min_score,
        check_tor_exit_nodes=cfg.filtering.check_tor_exit_nodes,
        mode=cfg.filtering.mode,
    )

    logger_db = LoggerDB(str(cfg.resolve_path(cfg.logging.db_path)))
    notifier = TelegramNotifier(cfg.telegram.enabled, cfg.telegram.bot_token, cfg.telegram.chat_id)
    firewall = FirewallManager(cfg.firewall.enabled)

    server = build_proxy_server(
        cfg.proxy.host, cfg.proxy.port, filter_engine, logger_db, notifier, firewall, allowlist
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureProxy] escuchando en {cfg.proxy.host}:{cfg.proxy.port}")
    if cfg.filtering.mode == "audit":
        print("[SecureProxy] modo: AUDIT (registra qué bloquearía, pero deja pasar todo el tráfico)")
    else:
        print("[SecureProxy] modo: enforce (bloquea de verdad)")
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

    light_reload_thread = threading.Thread(
        target=_light_reload_loop,
        args=(blocklist, allowlist, ip_blocklist),
        daemon=True,
    )
    light_reload_thread.start()

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
