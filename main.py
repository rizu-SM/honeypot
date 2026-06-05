import signal
import sys
import threading

from honeypot.core.config import load_config
from honeypot.core.logger import setup_logging, get_logger
from honeypot.core.database import Database
from honeypot.core.event_bus import EventBus
from honeypot.intelligence.geoip import GeoIPService
from honeypot.alerts.discord_alert import DiscordAlerter
from honeypot.services.ftp_honeypot import FTPHoneypot
from honeypot.services.telnet_honeypot import TelnetHoneypot
from honeypot.services.ssh_honeypot import SSHHoneypot
from honeypot.services.http_honeypot import HTTPHoneypot
from honeypot.dashboard.app import create_dashboard_app


def main():
    # ── 1. Config & logging ───────────────────────────────
    config = load_config()
    setup_logging(config)
    logger = get_logger("honeypot.main")
    logger.info("HoneyTrap starting")

    # ── 2. Database ───────────────────────────────────────
    db = Database(config.data_dir / "honeypot.db")

    # ── 3. Intelligence & alerts ──────────────────────────
    geoip   = GeoIPService(config, db)
    discord = DiscordAlerter(config)

    # ── 4. Event bus ──────────────────────────────────────
    bus = EventBus()

    def handle_event(event: dict):
        event_id = db.insert_event(event)
        geoip.enrich_async(event_id, event.get("source_ip", ""))
        discord.handle(event)

    bus.subscribe(handle_event)
    bus.start()

    # ── 5. Honeypot services ──────────────────────────────
    services = [
        FTPHoneypot(config, bus),
        TelnetHoneypot(config, bus),
        SSHHoneypot(config, bus),
        HTTPHoneypot(config, bus),
    ]
    for svc in services:
        svc.start()

    # ── 6. Dashboard ──────────────────────────────────────
    dashboard_app = create_dashboard_app(config, db)
    threading.Thread(
        target=lambda: dashboard_app.run(
            host="0.0.0.0",
            port=config.dashboard_port,
            threaded=True,
            use_reloader=False,
            debug=False,
        ),
        daemon=True,
        name="Dashboard",
    ).start()

    logger.info("HoneyTrap ready", extra={"extra": {
        "ssh":       config.ssh_port,
        "ftp":       config.ftp_port,
        "telnet":    config.telnet_port,
        "http":      config.http_port,
        "dashboard": config.dashboard_port,
    }})

    # ── 7. Graceful shutdown ──────────────────────────────
    stop = threading.Event()

    def shutdown(sig, frame):
        logger.info("Shutdown signal received")
        for svc in services:
            svc.stop()
        stop.set()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    stop.wait()
    logger.info("HoneyTrap stopped")
    sys.exit(0)


if __name__ == "__main__":
    main()
