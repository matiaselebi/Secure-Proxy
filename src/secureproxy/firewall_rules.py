"""Generación (y opcionalmente ejecución) de reglas de firewall de bloqueo dinámico.

Detecta el sistema operativo: usa `iptables` en Linux (Kali, etc.) y
`netsh advfirewall` en Windows. Por defecto solo genera el comando y lo
loguea (dry-run); si `enabled=True` en la config, lo ejecuta de verdad con
subprocess (requiere permisos de administrador/root en ambos casos).
"""

import platform
import subprocess


class FirewallManager:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.system = platform.system()  # "Windows", "Linux", "Darwin"
        self._already_blocked_ips: set[str] = set()

    def build_block_command(self, ip: str) -> list[str]:
        if self.system == "Windows":
            rule_name = f"SecureProxy_Block_{ip.replace('.', '_')}"
            return [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                f"remoteip={ip}",
            ]
        # Linux (Kali, etc.)
        return ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]

    def block_ip(self, ip: str) -> str:
        """Devuelve el comando (como string) que se generó o ejecutó."""
        if ip in self._already_blocked_ips:
            return f"(ya bloqueada previamente: {ip})"

        command = self.build_block_command(ip)
        command_str = " ".join(command)

        if self.enabled:
            try:
                subprocess.run(command, check=True, capture_output=True)
                self._already_blocked_ips.add(ip)
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                return f"ERROR ejecutando '{command_str}': {exc}"
        else:
            self._already_blocked_ips.add(ip)

        return command_str
