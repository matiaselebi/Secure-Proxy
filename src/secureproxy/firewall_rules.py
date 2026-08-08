"""Generación (y opcionalmente ejecución) de reglas de firewall de bloqueo dinámico.

Detecta el sistema operativo: usa `iptables` en Linux (Kali, etc.) y
`netsh advfirewall` en Windows. Por defecto solo genera el comando y lo
loguea (dry-run); si `enabled=True` en la config, lo ejecuta de verdad con
subprocess (requiere permisos de administrador/root en ambos casos).
"""

import ipaddress
import platform
import subprocess
import threading


class FirewallManager:
    def __init__(self, enabled: bool = False, hips=None):
        self.enabled = enabled
        self.system = platform.system()  # "Windows", "Linux", "Darwin"
        self._already_blocked_ips: set[str] = set()
        self._lock = threading.Lock()
        # Cliente de SecureHIPS. Si está configurado y contesta, el bloqueo lo
        # pone él y acá no se escribe ninguna regla. Ver `hips_client.py`: el
        # HIPS tiene vencimiento, lista blanca y registro; esta clase no.
        self.hips = hips

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
        """Devuelve el comando (como string) que se generó o ejecutó.

        Se valida que `ip` sea realmente una dirección antes de armar nada.
        Hoy siempre llega de `gethostbyname`, así que no hay por dónde
        colarse, pero esta función construye una línea de comando: si mañana
        alguien la llama desde el panel, el chequeo ya está puesto.
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"(no es una IP valida: {ip})"

        # Primero se le pregunta a SecureHIPS. Si lo toma, acá no se escribe
        # nada: un bloqueo puesto por los dos lados es una regla duplicada que
        # el HIPS no va a poder levantar cuando venza, porque la otra no es
        # suya. Ver ADR 0006 en SecureHIPS.
        #
        # Ojo con el orden: esto va ANTES del set de ya-bloqueadas a propósito.
        # Ese set es la memoria de las reglas que escribió ESTA clase; las que
        # pone el HIPS las recuerda el HIPS, que además sabe cuándo vencen.
        if self.hips is not None and getattr(self.hips, "configurado", bool)():
            tomado, detalle = self.hips.bloquear(ip, motivo="conexión saliente bloqueada")
            if tomado:
                return detalle
            # No lo tomó: seguimos como siempre. La herramienta no puede
            # quedarse sin bloquear porque la otra esté apagada.

        with self._lock:
            if ip in self._already_blocked_ips:
                return f"(ya bloqueada previamente: {ip})"
            # Solo se anota cuando la regla se escribió DE VERDAD. Antes se
            # anotaba también en dry-run, y eso tenía una consecuencia fea:
            # el usuario apretaba "Activar" en el panel y justamente las IPs
            # reincidentes -las que lo motivaron a activarlo- nunca recibían
            # regla, porque figuraban como ya bloqueadas.
            if self.enabled:
                self._already_blocked_ips.add(ip)

        command = self.build_block_command(ip)
        command_str = " ".join(command)

        if not self.enabled:
            return command_str

        try:
            subprocess.run(command, check=True, capture_output=True, timeout=30)
        except (subprocess.CalledProcessError, FileNotFoundError,
                subprocess.TimeoutExpired, OSError) as exc:
            with self._lock:
                # No quedó puesta: que se pueda reintentar.
                self._already_blocked_ips.discard(ip)
            return f"ERROR ejecutando '{command_str}': {exc}"

        return command_str
