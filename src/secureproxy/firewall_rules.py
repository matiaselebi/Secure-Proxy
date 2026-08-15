"""Pedirle un bloqueo a SecureHIPS. Ya no se escribe ninguna regla acá.

QUÉ PASÓ CON ESTE ARCHIVO

Tenía código que armaba un `netsh advfirewall` o un `iptables` y lo ejecutaba.
Funcionaba. Se borró igual, y el motivo es la regla número uno de la suite:
**un solo dueño del firewall**.

Dos programas escribiendo reglas es un firewall que nadie puede auditar ni
limpiar. Y era peor que eso: las reglas que ponía este archivo no vencían, no
consultaban tu lista blanca y no quedaban registradas como bloqueos. Una IP
bloqueada por error a las tres de la mañana seguía bloqueada en marzo, sin
ninguna fila en ninguna base que dijera por qué.

SecureHIPS ya tiene todo eso construido y probado: vencimiento, escalera de
duraciones, lista blanca, país, motivo y un botón para levantarla. Así que el
proxy pide y el HIPS decide. Ver el ADR 0006 de SecureHIPS.

QUÉ PASA SI EL HIPS NO ESTÁ

No se bloquea, y **se dice**. Antes había un camino de respaldo que escribía la
regla local, y ese camino era justamente el problema: hacía que el firewall
tuviera dos dueños cada vez que el HIPS estaba apagado, que es cuando menos se
mira. Ahora la respuesta es honesta ("no bloqueé nada porque el que bloquea no
está"), se ve en el panel, y se arregla prendiendo el HIPS.

Es la fase 2 del punto 8: borrarle a SecureProxy todo lo que ahora hacen
otros. Lo que queda no toca el sistema.
"""

import ipaddress
import threading


class FirewallManager:
    """Le pide bloqueos a SecureHIPS. No escribe reglas.

    Se mantiene el nombre de la clase aunque ya no administre ningún firewall:
    la usan el servidor y el panel, y renombrarla sería un cambio de
    superficie que no aporta nada. Lo que cambió es lo que hace adentro.
    """

    def __init__(self, enabled: bool = False, hips=None):
        # `enabled` ya no habilita escribir reglas: habilita PEDIRLAS. Se
        # conserva para que el interruptor del panel siga significando lo
        # mismo desde afuera: "¿esto puede terminar en un bloqueo real?".
        self.enabled = enabled
        self.hips = hips
        self._pedidos: set[str] = set()
        self._lock = threading.Lock()

    def disponible(self) -> bool:
        """¿Hay alguien del otro lado que pueda bloquear de verdad?"""
        return self.hips is not None and bool(
            getattr(self.hips, "configurado", lambda: False)())

    def block_ip(self, ip: str) -> str:
        """Pide el bloqueo. Devuelve qué pasó, en una frase para mostrar.

        Nunca lanza y nunca toca el sistema. Lo peor que puede devolver es
        "no lo bloqueé", que es una respuesta honesta y no un silencio.
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            # Se valida aunque hoy la IP siempre venga de `gethostbyname`: es
            # un dato que viaja a otro proceso por la red.
            return f"(no es una IP válida: {ip})"

        if not self.enabled:
            return f"(bloqueo desactivado; se habría pedido el de {ip})"

        if not self.disponible():
            # Antes acá se escribía una regla local. Eso es exactamente lo que
            # se sacó: el respaldo hacía que el firewall tuviera dos dueños
            # justo cuando el HIPS estaba apagado, que es cuando menos se mira.
            return ("no bloqueé nada: SecureHIPS no está configurado o no "
                    "responde, y es el único que escribe en el firewall")

        with self._lock:
            if ip in self._pedidos:
                return f"(ya se le pidió a SecureHIPS: {ip})"

        tomado, detalle = self.hips.bloquear(
            ip, motivo="conexión saliente bloqueada")
        if tomado:
            with self._lock:
                self._pedidos.add(ip)
        return detalle
