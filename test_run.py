"""
Temporary test script — wires up everything we've built so far and starts all services.
Run with: python test_run.py
"""
import signal
import threading
import time

from honeypot.core.config import load_config
from honeypot.core.logger import setup_logging
from honeypot.core.database import Database
from honeypot.core.event_bus import EventBus
from honeypot.services.ftp_honeypot import FTPHoneypot
from honeypot.services.telnet_honeypot import TelnetHoneypot
from honeypot.services.ssh_honeypot import SSHHoneypot
from honeypot.services.http_honeypot import HTTPHoneypot
from honeypot.intelligence.geoip import GeoIPService
from honeypot.alerts.discord_alert import DiscordAlerter
from honeypot.dashboard.app import create_dashboard_app

# 1. Load config and setup logging
config = load_config()
setup_logging(config)

# 2. Setup database
db = Database(config.data_dir / "honeypot.db")

# 3. Setup intelligence + alerts
geoip   = GeoIPService(config, db)
discord = DiscordAlerter(config)

# 4. Setup event bus
bus = EventBus()

def handle_event(event: dict):
    event_id = db.insert_event(event)                          # 1. save to DB
    geoip.enrich_async(event_id, event.get("source_ip", ""))   # 2. lookup geo
    discord.handle(event)                                      # 3. maybe alert
    print(f"  Discord counter: {discord._counter} / {discord.threshold}")
    print(f"  Webhook set:     {bool(discord.webhook_url)}")

bus.subscribe(handle_event)

# Simple print subscriber so we can see events in terminal
def print_event(event):
    print(f"\n{'='*50}")
    print(f"  NEW EVENT CAPTURED")
    print(f"  Protocol : {event.get('protocol')}")
    print(f"  IP       : {event.get('source_ip')}")
    print(f"  Username : {event.get('username', '-')}")
    print(f"  Password : {event.get('password', '-')}")
    print(f"  Path     : {event.get('path', '-')}")
    print(f"{'='*50}\n")

bus.subscribe(print_event)
bus.start()

# 4. Start all services
services = [
    FTPHoneypot(config, bus),
    TelnetHoneypot(config, bus),
    SSHHoneypot(config, bus),
    HTTPHoneypot(config, bus),
]

for svc in services:
    svc.start()

# Start dashboard in a background thread
dashboard_app = create_dashboard_app(config, db)
dashboard_thread = threading.Thread(
    target=lambda: dashboard_app.run(
        host="0.0.0.0",
        port=config.dashboard_port,
        threaded=True,
        use_reloader=False,
        debug=False,
    ),
    daemon=True,
    name="Dashboard",
)
dashboard_thread.start()

print(f"""
HoneyTrap running. Test each service:

  SSH       →  ssh root@localhost -p {config.ssh_port}
  FTP       →  ftp localhost {config.ftp_port}
  Telnet    →  telnet localhost {config.telnet_port}
  HTTP trap →  http://localhost:{config.http_port}/.env
  Dashboard →  http://localhost:{config.dashboard_port}

Press Ctrl+C to stop.
""")

# 5. Keep running until Ctrl+C
stop = threading.Event()
signal.signal(signal.SIGINT, lambda s, f: stop.set())
stop.wait()
print("Stopped.")
