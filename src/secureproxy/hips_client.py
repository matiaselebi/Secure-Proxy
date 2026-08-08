"""Le pide a SecureHIPS que bloquee una IP, en vez de escribir la regla acá.

POR QUÉ

SecureProxy sabe MUY bien cuándo una IP es mala: tiene los feeds, la
reputación de AbuseIPDB y ve el tráfico saliente. Lo que no tiene es un
sistema de bloqueos. Su `FirewallManager` arma una regla y la escribe, y esa
regla no vence nunca, no consulta ninguna lista blanca y no queda anotada en
ningún lado con motivo, país y un botón para levantarla.

SecureHIPS tiene exactamente eso, construido y probado. Así que el proxy
detecta y pide; el HIPS bloquea. Ver ADR 0006 en SecureHIPS.

SI EL HIPS NO ESTÁ

No pasa nada malo, y esa es la parte importante del diseño. Si no contesta,
el proxy hace lo mismo que hacía antes: escribe la regla él, o la loguea si
el bloqueo por firewall está apagado. Nunca se queda esperando ni deja pasar
tráfico que iba a cortar. Una integración que rompe al proxy cuando la otra
herramienta está apagada es peor que no tener integración.

LOS DOS DETALLES QUE PARECEN CHICOS Y NO LO SON

- **Se saltea el proxy del sistema.** Cuando el núcleo está prendido, el
  proxy del sistema es este mismo programa. Un `urlopen` normal mandaría el
  pedido a `127.0.0.1:8892` A TRAVÉS de sí mismo, o sea que el proxy se
  llamaría solo para avisarse de un bloqueo. `ProxyHandler({})` corta eso.
- **Hay un fusible.** Si el HIPS está colgado (no apagado: colgado), cada
  pedido esperaría el timeout completo, y esto se llama desde el camino de
  una conexión. Después de tres fallas seguidas se deja de intentar por un
  minuto. Con el HIPS apagado el costo es cero igual, porque conectarse a un
  puerto cerrado falla al instante.
"""

import json
import threading
import time
import urllib.error
import urllib.request

# Corto a propósito: esto se llama mientras se está atendiendo una conexión.
# Es un pedido a localhost, así que si tarda más de esto es que algo está mal.
TIMEOUT = 2.0

# Cuántas fallas seguidas abren el fusible, y por cuánto tiempo queda abierto.
FALLAS_PARA_CORTAR = 3
SEGUNDOS_DE_CORTE = 60


class ClienteHIPS:
    """Cliente del endpoint de bloqueo de SecureHIPS."""

    def __init__(self, url: str = "", token: str = "", timeout: float = TIMEOUT):
        self.url = (url or "").strip().rstrip("/")
        self.token = (token or "").strip()
        self.timeout = float(timeout)
        self._lock = threading.Lock()
        self._fallas = 0
        self._cortado_hasta = 0.0
        # Para el panel: cuántos pedidos salieron bien y cuántos no.
        self.aceptados = 0
        self.rechazados = 0
        self.ultimo_error = ""

    def configurado(self) -> bool:
        """¿Hay a dónde pedir y con qué credencial?"""
        return bool(self.url and self.token)

    def por_que_no(self) -> str:
        if not self.url:
            return "no hay hips.url en el config"
        if not self.token:
            return "no hay SECUREHIPS_API_TOKEN en el archivo .env"
        return ""

    # ------------------------------------------------------------ fusible

    def _disponible(self) -> bool:
        with self._lock:
            return time.time() >= self._cortado_hasta

    def _anotar_falla(self) -> None:
        with self._lock:
            self._fallas += 1
            if self._fallas >= FALLAS_PARA_CORTAR:
                self._cortado_hasta = time.time() + SEGUNDOS_DE_CORTE
                self._fallas = 0

    def _anotar_exito(self) -> None:
        with self._lock:
            self._fallas = 0
            self._cortado_hasta = 0.0

    # ------------------------------------------------------------ pedido

    def bloquear(self, ip: str, motivo: str = "") -> tuple[bool, str]:
        """Pide el bloqueo. Devuelve (lo tomó el HIPS, qué contestó).

        `False` quiere decir "encargate vos", no "hubo un error grave". El que
        llama tiene que poder seguir su camino de siempre con eso.
        """
        if not self.configurado():
            return False, f"SecureHIPS no configurado ({self.por_que_no()})"
        if not self._disponible():
            return False, "SecureHIPS no venía contestando; no lo intento por un rato"

        cuerpo = json.dumps({
            "ip": ip, "origen": "secureproxy", "motivo": motivo,
        }).encode("utf-8")
        pedido = urllib.request.Request(
            f"{self.url}/api/bloquear", data=cuerpo, method="POST",
            headers={
                "Content-Type": "application/json",
                # En un header y no en la URL: una URL con el token adentro
                # termina en los logs y en el historial del navegador.
                "Authorization": f"Bearer {self.token}",
            },
        )
        # Sin esto, el pedido saldría a través del proxy del sistema, que
        # cuando el núcleo está prendido es este mismo programa.
        abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with abridor.open(pedido, timeout=self.timeout) as respuesta:
                datos = json.loads(respuesta.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            # Un 401 o un 400 no son "el HIPS está caído": está vivo y dijo que
            # no. No abren el fusible, porque reintentar no lo va a arreglar,
            # pero tampoco tiene sentido dejar de hablarle.
            self.rechazados += 1
            self.ultimo_error = f"HTTP {exc.code}"
            return False, f"SecureHIPS rechazó el pedido (HTTP {exc.code})"
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            self._anotar_falla()
            self.rechazados += 1
            self.ultimo_error = str(exc)
            return False, f"no pude hablar con SecureHIPS: {exc}"

        self._anotar_exito()
        if not datos.get("ok"):
            # El caso más común y el más valioso: la IP está en la lista
            # blanca del HIPS. El proxy NO tiene que bloquearla por su cuenta,
            # porque eso sería justamente saltearse la lista blanca.
            self.rechazados += 1
            razon = datos.get("razon") or datos.get("error") or "sin detalle"
            return True, f"SecureHIPS no la bloqueó: {razon}"

        self.aceptados += 1
        if datos.get("aplicado"):
            return True, f"bloqueada por SecureHIPS ({ip})"
        return True, (f"SecureHIPS la registró pero NO la bloqueó: está en modo "
                      f"{datos.get('modo') or 'audit'}")
