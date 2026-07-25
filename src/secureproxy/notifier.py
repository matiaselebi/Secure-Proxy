"""Envío de alertas por Telegram cuando el proxy bloquea algo."""

import requests


class TelegramNotifier:
    API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, enabled: bool, bot_token: str, chat_id: str):
        self.enabled = enabled and bool(bot_token) and bool(chat_id)
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send_alert(self, message: str) -> None:
        if not self.enabled:
            return
        try:
            requests.post(
                self.API_URL_TEMPLATE.format(token=self.bot_token),
                data={"chat_id": self.chat_id, "text": message},
                timeout=5,
            )
        except requests.RequestException:
            # Una alerta que falla no debería tumbar el proxy.
            pass
