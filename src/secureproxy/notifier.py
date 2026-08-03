"""Envío de alertas por Telegram cuando el proxy bloquea algo."""

import threading

import requests

from . import http_client


class TelegramNotifier:
    API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"

    # Techo de envíos en vuelo. Si Telegram no responde y el proxy está
    # bloqueando mucho, no tiene sentido acumular hilos esperando.
    MAX_EN_VUELO = 8

    def __init__(self, enabled: bool, bot_token: str, chat_id: str):
        self.enabled = enabled and bool(bot_token) and bool(chat_id)
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._en_vuelo = 0
        self._lock = threading.Lock()

    def send_alert(self, message: str) -> None:
        """Manda la alerta SIN esperarla.

        Antes esto era una llamada de red sincrónica con 5 segundos de
        timeout, hecha en el mismo hilo que atiende la conexión y justo
        antes de responderle al cliente. O sea: con Telegram lento o
        inalcanzable -que es exactamente lo que pasa cuando la red anda
        mal- cada bloqueo demoraba 5 segundos el 403, y una ráfaga de
        bloqueos dejaba al navegador colgado. El aviso de escritorio ya se
        había hecho asincrónico por este mismo motivo; esto quedó atrás.
        """
        if not self.enabled:
            return
        with self._lock:
            if self._en_vuelo >= self.MAX_EN_VUELO:
                return
            self._en_vuelo += 1
        threading.Thread(target=self._enviar, args=(message,), daemon=True).start()

    def _enviar(self, message: str) -> None:
        try:
            # http_client, no requests: si la alerta saliera por el proxy
            # del sistema, sería este mismo proxy mandándose trabajo a sí
            # mismo cada vez que bloquea algo (ver http_client.py).
            http_client.post(
                self.API_URL_TEMPLATE.format(token=self.bot_token),
                data={"chat_id": self.chat_id, "text": message},
                timeout=5,
            )
        except requests.RequestException:
            # Una alerta que falla no debería tumbar el proxy.
            pass
        finally:
            with self._lock:
                self._en_vuelo -= 1
