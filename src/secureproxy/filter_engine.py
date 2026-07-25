"""Motor de decisión: junta blocklist + AbuseIPDB + nodos TOR y decide bloquear o no."""

from dataclasses import dataclass

from .threat_intel import AbuseIPDBClient, Blocklist, TorExitNodeList, resolve_host_to_ip


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
        abuseipdb_min_score: int = 50,
        check_tor_exit_nodes: bool = True,
    ):
        self.blocklist = blocklist
        self.abuseipdb_client = abuseipdb_client
        self.tor_list = tor_list
        self.abuseipdb_min_score = abuseipdb_min_score
        self.check_tor_exit_nodes = check_tor_exit_nodes

    def evaluate(self, host: str) -> FilterDecision:
        """Decide si una conexión hacia `host` debe bloquearse.

        Orden de chequeo (de más barato a más caro): blocklist local por
        dominio, luego resolución DNS + reputación de IP.
        """
        if self.blocklist.is_blocked(host):
            return FilterDecision(blocked=True, reason=f"dominio en blocklist: {host}")

        resolved_ip = resolve_host_to_ip(host)
        if resolved_ip is None:
            # No se pudo resolver el dominio: dejamos pasar (el intento de
            # conexión real va a fallar solo) en vez de bloquear a ciegas.
            return FilterDecision(blocked=False, resolved_ip=None)

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
