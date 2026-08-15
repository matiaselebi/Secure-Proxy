"""Motor de decisión: allowlist + blocklist + IPBlocklist (Feodo Tracker) +
AbuseIPDB + nodos TOR, y decide bloquear o no."""

import ipaddress
from dataclasses import dataclass

from .threat_intel import (
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
    resolve_host_to_ip,
)
from .validation import normalizar_host_de_trafico


def _es_ip_interna(ip: str) -> bool:
    """Loopback, redes privadas, link-local y compañía.

    Se chequea sobre la IP YA RESUELTA y no solo sobre el texto del host,
    porque un nombre público puede apuntar tranquilamente a 127.0.0.1 o a
    192.168.x. Sin esto, la política de destino se esquiva registrando un
    dominio que apunte adonde uno quiera.
    """
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(
        direccion.is_loopback
        or direccion.is_private
        or direccion.is_link_local
        or direccion.is_reserved
        or direccion.is_multicast
        or direccion.is_unspecified
    )


@dataclass
class FilterDecision:
    blocked: bool
    reason: str = ""
    resolved_ip: str | None = None
    # True cuando el modo "audit" evitó que un bloqueo real se aplicara: la
    # conexión se dejó pasar igual, pero queda constancia de qué hubiera
    # pasado en modo "enforce". Ver FilterEngine.mode.
    would_have_blocked: bool = False


# Modos de operación del motor de filtrado:
#   "enforce" (default): aplica los bloqueos normalmente.
#   "audit": evalúa y registra qué se HUBIERA bloqueado, pero deja pasar
#            todo el tráfico. Pensado para probar reglas nuevas (una lista
#            negra recién agregada, un umbral de AbuseIPDB distinto) sin
#            riesgo de cortar algo legítimo mientras se observa el efecto
#            real en el dashboard/logs.
VALID_MODES = ("enforce", "audit")


class FilterEngine:
    def __init__(
        self,
        blocklist: Blocklist,
        abuseipdb_client: AbuseIPDBClient,
        tor_list: TorExitNodeList,
        ip_blocklist: IPBlocklist | None = None,
        allowlist: Allowlist | None = None,
        abuseipdb_min_score: int = 50,
        check_tor_exit_nodes: bool = True,
        mode: str = "enforce",
        mining_list=None,
        ip_ranges=None,
        block_unknown_domains: bool = False,
        allow_internal_destinations: bool = False,
    ):
        if mode not in VALID_MODES:
            raise ValueError(f"mode inválido: {mode!r} (válidos: {VALID_MODES})")
        self.blocklist = blocklist
        self.abuseipdb_client = abuseipdb_client
        self.tor_list = tor_list
        self.ip_blocklist = ip_blocklist
        self.allowlist = allowlist
        self.abuseipdb_min_score = abuseipdb_min_score
        self.check_tor_exit_nodes = check_tor_exit_nodes
        self.mode = mode
        # Lista de pools de minería. Va aparte de la blocklist general para
        # que el motivo del bloqueo diga "cryptojacking" y no un genérico
        # "dominio en blocklist": cuando esto salta, lo que hay que hacer no
        # es agregar una excepción sino buscar qué proceso se conectó.
        self.mining_list = mining_list
        # Rangos de IP con mala reputación (FireHOL). Distinto de
        # ip_blocklist, que compara IPs exactas.
        self.ip_ranges = ip_ranges
        # Modo lista blanca: cualquier dominio que no esté explícitamente
        # permitido se bloquea. En una PC de uso diario rompe todo, así que
        # se usa junto con mode="audit" para descubrir qué habría que
        # permitir antes de aplicarlo en serio.
        self.block_unknown_domains = block_unknown_domains
        # Permitir salir hacia loopback y redes privadas. Apagado por
        # defecto: sin esto, el proxy es un pivote hacia los servicios
        # internos de la máquina y de la LAN.
        self.allow_internal_destinations = allow_internal_destinations

    def evaluate(self, host: str) -> FilterDecision:
        """Decide si una conexión hacia `host` debe bloquearse.

        Orden de chequeo: primero la allowlist (gana por sobre todo lo
        demás), después blocklist local por dominio, lista de IPs de C2
        conocidas (Feodo Tracker), nodos TOR, y por último reputación de IP
        vía AbuseIPDB.

        En modo "audit", cualquier decisión que hubiera bloqueado se
        devuelve con blocked=False y would_have_blocked=True: la conexión
        pasa igual, pero la razón queda registrada tal cual se hubiera
        aplicado.
        """
        decision = self._evaluate_enforce(host)
        if self.mode == "audit" and decision.blocked:
            return FilterDecision(
                blocked=False,
                reason=f"[AUDIT] hubiera bloqueado: {decision.reason}",
                resolved_ip=decision.resolved_ip,
                would_have_blocked=True,
            )
        return decision

    def _evaluate_enforce(self, host: str) -> FilterDecision:
        # Se normaliza acá también, y no solo en el servidor, para que
        # cualquiera que llame al motor (los tests, el panel OSINT) compare
        # exactamente lo mismo que se compara en el camino del tráfico.
        host = normalizar_host_de_trafico(host) or host

        if self.allowlist is not None and self.allowlist.is_allowed(host):
            # La allowlist gana sobre reputación y listas de amenazas, pero no
            # sobre la barrera que impide usar el proxy como pivote hacia la
            # máquina o la LAN. Un nombre público permitido también puede
            # resolver a 127.0.0.1 o a una dirección privada.
            resolved_ip = resolve_host_to_ip(host)
            if (resolved_ip is not None
                    and not self.allow_internal_destinations
                    and _es_ip_interna(resolved_ip)):
                return FilterDecision(
                    blocked=True,
                    reason=f"{host} resuelve a la direccion interna {resolved_ip}",
                    resolved_ip=resolved_ip,
                )
            return FilterDecision(
                blocked=False, reason="dominio en allowlist", resolved_ip=resolved_ip)

        if self.mining_list is not None and self.mining_list.is_blocked(host):
            return FilterDecision(
                blocked=True,
                reason=f"pool de minería de criptomonedas (posible cryptojacking): {host}",
            )

        if self.blocklist.is_blocked(host):
            return FilterDecision(blocked=True, reason=f"dominio en blocklist: {host}")

        if self.block_unknown_domains:
            # Se chequea ANTES de resolver: si el dominio no está permitido,
            # no tiene sentido gastar una resolución de nombre.
            return FilterDecision(
                blocked=True,
                reason=f"dominio desconocido, no está en la lista blanca: {host}",
            )

        resolved_ip = resolve_host_to_ip(host)
        if resolved_ip is not None and not self.allow_internal_destinations:
            # El host puede ser un nombre público que apunta a 127.0.0.1 o a
            # la LAN. Chequear solo el texto del host dejaría abierto ese
            # camino, así que la política se vuelve a aplicar sobre la IP
            # que realmente se resolvió.
            if _es_ip_interna(resolved_ip):
                return FilterDecision(
                    blocked=True,
                    reason=f"{host} resuelve a la direccion interna {resolved_ip}",
                    resolved_ip=resolved_ip,
                )
        if resolved_ip is None:
            # No se pudo resolver el dominio: dejamos pasar (el intento de
            # conexión real va a fallar solo) en vez de bloquear a ciegas.
            return FilterDecision(blocked=False, resolved_ip=None)

        if self.ip_blocklist is not None and self.ip_blocklist.is_blocked(resolved_ip):
            return FilterDecision(
                blocked=True,
                reason=f"IP {resolved_ip} es un servidor de C2 conocido (Feodo Tracker)",
                resolved_ip=resolved_ip,
            )

        if self.ip_ranges is not None and self.ip_ranges.is_blocked(resolved_ip):
            return FilterDecision(
                blocked=True,
                reason=f"IP {resolved_ip} está en un rango de mala reputación (FireHOL)",
                resolved_ip=resolved_ip,
            )

        if self.check_tor_exit_nodes and self.tor_list.is_tor_exit_node(resolved_ip):
            return FilterDecision(
                blocked=True,
                reason=f"IP {resolved_ip} es un nodo de salida TOR conocido",
                resolved_ip=resolved_ip,
            )

        score = self.abuseipdb_client.get_abuse_score(resolved_ip)
        if score >= self.abuseipdb_min_score:
            return FilterDecision(
                blocked=True,
                reason=f"IP {resolved_ip} con score de abuso {score} (AbuseIPDB)",
                resolved_ip=resolved_ip,
            )

        return FilterDecision(blocked=False, resolved_ip=resolved_ip)
