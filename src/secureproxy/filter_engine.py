"""Motor de decisión: allowlist + blocklist + IPBlocklist (Feodo Tracker) +
AbuseIPDB + nodos TOR, y decide bloquear o no."""

from dataclasses import dataclass

from .threat_intel import (
    AbuseIPDBClient,
    Allowlist,
    Blocklist,
    IPBlocklist,
    TorExitNodeList,
    resolve_host_to_ip,
)


@dataclass
class FilterDecision:
    blocked: bool
    reason: str = ""
    resolved_ip: str | None = None


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
    ):
        self.blocklist = blocklist
        self.abuseipdb_client = abuseipdb_client
        self.tor_list = tor_list
        self.ip_blocklist = ip_blocklist
        self.allowlist = allowlist
        self.abuseipdb_min_score = abuseipdb_min_score
        self.check_tor_exit_nodes = check_tor_exit_nodes

    def evaluate(self, host: str) -> FilterDecision:
        """Decide si una conexión hacia `host` debe bloquearse.

        Orden de chequeo: primero la allowlist (gana por sobre todo lo
        demás), después blocklist local por dominio, lista de IPs de C2
        conocidas (Feodo Tracker), nodos TOR, y por último reputación de IP
        vía AbuseIPDB.
        """
        if self.allowlist is not None and self.allowlist.is_allowed(host):
            return FilterDecision(blocked=False, reason="dominio en allowlist")

        if self.blocklist.is_blocked(host):
            return FilterDecision(blocked=True, reason=f"dominio en blocklist: {host}")

        resolved_ip = resolve_host_to_ip(host)
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
