import threading

import requests

from honeypot.core.config import Config
from honeypot.core.logger import get_logger

logger = get_logger(__name__)

# Color codes for Discord embeds (left border color)
PROTOCOL_COLORS = {
    "SSH":         0x3498DB,   # blue
    "SSH_SESSION": 0x2980B9,   # dark blue
    "FTP":         0xE67E22,   # orange
    "Telnet":      0xE74C3C,   # red
    "HTTP":        0x2ECC71,   # green
}
DEFAULT_COLOR = 0x95A5A6       # grey


class DiscordAlerter:
    """
    Sends attack notifications to a Discord channel via webhook.
    Fires an alert every N attacks (configurable threshold).
    No-op if DISCORD_WEBHOOK_URL is not set in .env.
    """

    def __init__(self, config: Config):
        self.webhook_url = config.discord_webhook_url
        self.threshold   = config.discord_alert_threshold
        self._counter    = 0
        self._lock       = threading.Lock()   # thread-safe counter

    def handle(self, event: dict) -> None:
        """
        Called for every event by the EventBus.
        Increments counter and sends alert when threshold is reached.
        """
        if not self.webhook_url:
            return   # webhook not configured — silently skip

        with self._lock:
            self._counter += 1
            if self._counter >= self.threshold:
                self._send_alert(event)
                self._counter = 0   # reset after alert

    def _send_alert(self, event: dict) -> None:
        """Build a Discord embed and POST it to the webhook URL."""
        protocol = event.get("protocol", "UNKNOWN")
        color    = PROTOCOL_COLORS.get(protocol, DEFAULT_COLOR)

        # Build fields — only include fields that have values
        fields = []

        if event.get("username"):
            fields.append({
                "name":   "Username",
                "value":  event["username"],
                "inline": True,
            })
        if event.get("password"):
            fields.append({
                "name":   "Password",
                "value":  event["password"],
                "inline": True,
            })
        if event.get("path"):
            fields.append({
                "name":   "Path",
                "value":  event["path"],
                "inline": True,
            })
        if event.get("country"):
            fields.append({
                "name":   "Country",
                "value":  event["country"],
                "inline": True,
            })

        payload = {
            "embeds": [{
                "title":       f"[{protocol}] Attack from {event.get('source_ip', 'unknown')}",
                "description": f"**{self.threshold}** attacks reached — showing latest",
                "color":       color,
                "fields":      fields,
                "timestamp":   event.get("timestamp"),
                "footer": {
                    "text": "HoneyTrap"
                },
            }]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5,
            )
            if response.status_code == 204:
                logger.info("Discord alert sent", extra={"extra": {
                    "protocol": protocol,
                    "ip": event.get("source_ip"),
                }})
            else:
                logger.warning("Discord alert failed", extra={"extra": {
                    "status": response.status_code,
                }})
        except Exception:
            logger.exception("Discord alert error")
