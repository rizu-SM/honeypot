import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Config:
    # Ports each honeypot service listens on
    ssh_port: int = 2222
    http_port: int = 8080
    ftp_port: int = 2121
    telnet_port: int = 2323
    dashboard_port: int = 5000

    # Where to store the database file and log files
    data_dir: Path = Path("data")
    log_dir: Path = Path("logs")

    # GeoIP — how many IPs to keep in memory cache
    geoip_cache_size: int = 1024

    # Optional: AbuseIPDB API key for threat reputation scores
    abuseipdb_api_key: str = ""

    # Optional: Discord webhook for attack notifications
    discord_webhook_url: str = ""
    discord_alert_threshold: int = 10  # send alert every N attacks

    # Flask session security key — change this in production
    dashboard_secret_key: str = "dev-secret-change-me"

    # How verbose the logs are: DEBUG, INFO, WARNING, ERROR
    log_level: str = "INFO"


def load_config() -> Config:
    # Read the .env file and push values into os.environ
    load_dotenv()

    cfg = Config(
        ssh_port=int(os.environ.get("SSH_PORT", 2222)),
        http_port=int(os.environ.get("HTTP_PORT", 8080)),
        ftp_port=int(os.environ.get("FTP_PORT", 2121)),
        telnet_port=int(os.environ.get("TELNET_PORT", 2323)),
        dashboard_port=int(os.environ.get("DASHBOARD_PORT", 5000)),

        data_dir=Path(os.environ.get("DATA_DIR", "data")),
        log_dir=Path(os.environ.get("LOG_DIR", "logs")),

        geoip_cache_size=int(os.environ.get("GEOIP_CACHE_SIZE", 1024)),

        abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY", ""),
        discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL", ""),
        discord_alert_threshold=int(os.environ.get("DISCORD_ALERT_THRESHOLD", 10)),

        dashboard_secret_key=os.environ.get("DASHBOARD_SECRET_KEY", "dev-secret-change-me"),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )

    # Create the folders if they don't exist yet
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)

    return cfg
