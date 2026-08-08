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
from secureproxy.hips_client import ClienteHIPS  # noqa: E402
from secureproxy.logger_db import LoggerDB  # noqa: E402
from secureproxy.ip_reputation_cache import PersistentIPCache  # noqa: E402
from secureproxy.notifier import TelegramNotifier  # noqa: E402
from secureproxy.proxy_server import build_dashboard_server, build_proxy_server  # noqa: E402
from secureproxy.geoip import GeoIP  # noqa: E402
from secureproxy.desktop_alerts import DesktopNotifier  # noqa: E402
from secureproxy.process_lookup import ProcessLookup  # noqa: E402
from secureproxy.view_prefs import PreferenciasDeVista  # noqa: E402
from secureproxy.ip_ranges import IPRangeBlocklist  # noqa: E402
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


def _feeds_timer_loop(
    interval_hours: float, blocklist: Blocklist, ip_blocklist: IPBlocklist,
    ip_ranges: IPRangeBlocklist,
) -> None:
    """Vuelve a descargar los feeds cada `interval_hours`, mientras el proxy
    corre.

    Antes la actualización se intentaba UNA sola vez, al arrancar: si dejabas
    la PC prendida tres días, los feeds quedaban de hace tres días. El ciclo
    de 6 horas existía en la configuración pero solo servía para decidir si
    la descarga del arranque se hacía o se salteaba.
    """
    while True:
        time.sleep(max(interval_hours, 0.25) * 3600)
        try:
            if update_blocklist.main(force=False, min_interval_hours=interval_hours):
                blocklist.reload()
                ip_blocklist.reload()
                ip_ranges.reload()
                print("[SecureProxy] listas de amenazas actualizadas (ciclo automático).")
        except Exception as exc:  # noqa: BLE001 - no debe tumbar el proxy
            print(f"[SecureProxy] falló la actualización automática de listas: {exc}")


def _light_reload_loop(
    blocklist: Blocklist,
    allowlist: Allowlist,
    ip_blocklist: IPBlocklist,
    ip_ranges=None,
    mining_list=None,
    noise_list=None,
) -> None:
    """Vuelve a leer los archivos de listas cada pocos segundos, para que
    cualquier edición manual (menú .bat, editar el .txt a mano, etc.) se
    aplique sola sin reiniciar el proceso. No descarga nada de internet:
    eso lo sigue haciendo _update_feeds_in_background, por separado.

    Antes se recargaban solo tres listas: `ip_ranges` se recibía como
    parámetro y no se usaba, y `mining_list` ni siquiera se pasaba. O sea que
    los rangos nuevos de FireHOL que bajaba el botón "Sincronizar" no
    entraban en uso hasta reiniciar, y editar `mining_pools.txt` a mano no
    hacía absolutamente nada, en contra de lo que promete este docstring.
    """
    listas = [
        ("blocklist", blocklist),
        ("allowlist", allowlist),
        ("ip_blocklist", ip_blocklist),
        ("ip_ranges", ip_ranges),
        ("mining_list", mining_list),
        ("noise_list", noise_list),
    ]
    while True:
        time.sleep(LIGHT_RELOAD_INTERVAL_SECONDS)
        for nombre, lista in listas:
            if lista is None:
                continue
            try:
                lista.reload()
            except Exception as exc:  # noqa: BLE001 - no debe tumbar el proxy
                print(f"[SecureProxy] error recargando {nombre}: {exc}")


def _maintain_log_db(logger_db: LoggerDB) -> None:
    """Recorta el historial al arrancar, en un hilo aparte.

    Existe porque el problema aparece justamente en las máquinas que ya
    vienen usando el proxy hace rato: la base puede estar en cientos de MB
    antes de que este recorte existiera, y ahí el dashboard no abre. Al
    arrancar se poda una vez y el archivo vuelve a un tamaño sano solo, sin
    que haya que correr nada a mano.
    """
    try:
        borradas = logger_db.prune()
        if borradas:
            print(f"[SecureProxy] historial recortado: {borradas:,} conexiones viejas borradas.")
            logger_db.compact()
            print("[SecureProxy] base de logs compactada.")
    except Exception as exc:  # noqa: BLE001 - el mantenimiento no debe tumbar el proxy
        print(f"[SecureProxy] no se pudo recortar el historial: {exc}")


def main() -> None:
    cfg = load_config()

    blocklist = Blocklist(
        [
            str(cfg.resolve_path(cfg.filtering.blocklist_path)),
            str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path)),
        ]
    )
    ip_blocklist = IPBlocklist(str(cfg.resolve_path(cfg.filtering.ip_feeds_blocklist_path)))
    ip_ranges = IPRangeBlocklist(str(cfg.resolve_path(cfg.filtering.ip_ranges_feeds_path)))
    mining_list = Blocklist(str(cfg.resolve_path(cfg.filtering.mining_pools_path)))
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
        mining_list=mining_list,
        ip_ranges=ip_ranges,
        block_unknown_domains=cfg.filtering.block_unknown_domains,
        allow_internal_destinations=cfg.filtering.allow_internal_destinations,
    )

    logger_db = LoggerDB(
        str(cfg.resolve_path(cfg.logging.db_path)), max_rows=cfg.logging.max_rows
    )
    notifier = TelegramNotifier(cfg.telegram.enabled, cfg.telegram.bot_token, cfg.telegram.chat_id)
    # Si SecureHIPS está prendido y compartimos token, los bloqueos los pone
    # él: tienen vencimiento, pasan por su lista blanca y quedan registrados
    # con motivo y país. Si no está, el proxy hace exactamente lo de siempre.
    hips = ClienteHIPS(
        url=cfg.hips.url if cfg.hips.enabled else "",
        token=cfg.securehips_api_token,
    )
    firewall = FirewallManager(cfg.firewall.enabled, hips=hips)
    if hips.configurado():
        print(f"[SecureProxy] los bloqueos se le piden a SecureHIPS ({cfg.hips.url})")
    elif cfg.hips.enabled:
        print(f"[SecureProxy] SecureHIPS no está enganchado: {hips.por_que_no()}")

    # Las listas manuales se limpian una vez al arrancar: una entrada como
    # "https://www.ejemplo.com/algo" no matchea nunca, porque el proxy compara
    # contra el host. Era una regla que parecía puesta y no hacía nada.
    for nombre, lista in (("negra", blocklist), ("blanca", allowlist)):
        cambios = lista.normalizar_archivo()
        if cambios:
            print(f"[SecureProxy] se limpiaron {cambios} entradas de la lista {nombre}")

    # Filtro de VISTA: qué dominios tapan el panel. No decide nada de lo que
    # se bloquea, por eso se arma acá y no dentro del motor de filtrado.
    noise_list = Blocklist(str(cfg.resolve_path(cfg.dashboard.noisy_domains_path)))
    vista = PreferenciasDeVista(noise_list, ocultar_ruido=cfg.dashboard.hide_noise)
    # Se recalcula la marca sobre el historial que ya existía: así una base
    # vieja, o una lista editada a mano, quedan consistentes desde el primer
    # refresco del panel en vez de tener que esperar a que pase tráfico nuevo.
    cambios = logger_db.remarcar_ruido(vista.es_ruidoso)
    if cambios:
        print(f"[SecureProxy] se remarcaron {cambios:,} conexiones del historial".replace(",", "."))
    if cfg.dashboard.hide_noise:
        print(
            f"[SecureProxy] filtro de ruido del panel: {len(noise_list.dominios())} "
            "dominios de telemetría y comprobación ocultos (se apaga desde el panel)"
        )

    # Quién abrió cada conexión. Se resuelve por el puerto de origen contra
    # la tabla de sockets del sistema; si no se puede, la conexión se
    # registra igual, solo que sin ese dato.
    procesos = ProcessLookup(cfg.logging.identify_process)
    if cfg.logging.identify_process and not procesos.disponible:
        print("[SecureProxy] no puedo identificar procesos en este sistema; sigo sin ese dato")

    alertas = DesktopNotifier(cfg.alerts.enabled, cfg.alerts.only_severe)
    if cfg.alerts.enabled:
        estado = "activas" if alertas.disponible else "no disponibles en este sistema"
        print(f"[SecureProxy] avisos en el escritorio: {estado}")

    geoip = GeoIP(str(cfg.resolve_path(cfg.logging.geoip_db_path)))
    if geoip.disponible:
        print(f"[SecureProxy] geolocalización: {geoip.cantidad_de_rangos():,} rangos cargados")
    else:
        print("[SecureProxy] geolocalización: sin base (corré scripts/update_geoip.py)")

    server = build_proxy_server(
        cfg.proxy.host, cfg.proxy.port, filter_engine, logger_db, notifier, firewall, allowlist,
        geoip=geoip, vista=vista, procesos=procesos, alertas=alertas,
        max_threads=cfg.proxy.max_threads,
    )
    # Lo que levanta el botón "Apagar proxy" del panel. Se hace con un evento
    # y no mandándose una señal a sí mismo porque en Windows no hay forma
    # limpia de mandarle SIGINT a un proceso puntual: CTRL_C_EVENT va al grupo
    # de consola entero. Con el evento, el camino de apagado es exactamente el
    # mismo que el de Ctrl+C en los dos sistemas.
    detener = threading.Event()

    # El dashboard vive en su PROPIO puerto, separado del que proxea: mismo
    # proceso y mismo estado, distinto socket.
    dashboard_server = build_dashboard_server(
        cfg.proxy.host, cfg.proxy.dashboard_port, filter_engine, logger_db,
        notifier, firewall, allowlist, geoip=geoip, vista=vista, alertas=alertas,
        apagar=detener.set,
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureProxy] escuchando en {cfg.proxy.host}:{cfg.proxy.port}")
    print(f"[SecureProxy] dashboard: http://{cfg.proxy.host}:{cfg.proxy.dashboard_port}/")
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
        args=(blocklist, allowlist, ip_blocklist, ip_ranges, mining_list, noise_list),
        daemon=True,
    )
    light_reload_thread.start()

    feeds_timer = threading.Thread(
        target=_feeds_timer_loop,
        args=(cfg.filtering.feeds_update_interval_hours, blocklist, ip_blocklist, ip_ranges),
        daemon=True,
    )
    feeds_timer.start()

    mantenimiento_thread = threading.Thread(
        target=_maintain_log_db, args=(logger_db,), daemon=True
    )
    mantenimiento_thread.start()

    dashboard_thread = threading.Thread(target=dashboard_server.serve_forever, daemon=True)
    dashboard_thread.start()

    # El proxy también pasa a un hilo: el principal se queda esperando la
    # orden de apagar, venga de Ctrl+C o del botón del panel. Los dos caminos
    # terminan en el mismo `finally`, así que el cierre es idéntico.
    def _servir_proxy() -> None:
        try:
            server.serve_forever()
        except Exception as exc:  # noqa: BLE001
            # Si el bucle de aceptación se muere (el socket se cae, el sistema
            # se queda sin descriptores), el hilo principal tiene que
            # enterarse. Sin esto quedaría esperando para siempre una orden de
            # apagado que no va a llegar, con el panel arriba y el proxy
            # muerto: lo peor de los dos mundos.
            print(f"[SecureProxy] el proxy dejó de aceptar conexiones: {exc}")
        finally:
            detener.set()

    proxy_thread = threading.Thread(target=_servir_proxy, daemon=True)
    proxy_thread.start()

    try:
        # Con timeout y no `detener.wait()` a secas: en Windows, esperar sin
        # plazo sobre un lock puede tragarse el Ctrl+C hasta que el lock se
        # libere, y ahí el Ctrl+C parece no funcionar. Despertarse cada medio
        # segundo no cuesta nada y garantiza que la señal se atienda.
        while not detener.wait(0.5):
            pass
        print("\n[SecureProxy] apagando por pedido del panel...")
    except KeyboardInterrupt:
        print("\n[SecureProxy] deteniendo...")
    finally:
        server.shutdown()
        dashboard_server.shutdown()
        if PID_FILE.exists():
            PID_FILE.unlink()
        print("[SecureProxy] listo, todo cerrado.")


if __name__ == "__main__":
    main()
