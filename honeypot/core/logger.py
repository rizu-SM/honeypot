import json
import logging
import datetime
from logging.handlers import RotatingFileHandler

from honeypot.core.config import Config


class JSONFormatter(logging.Formatter):
    """Formats every log record as a single JSON object on one line."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # If the caller passed extra={...}, merge those fields in
        if hasattr(record, "extra"):
            entry.update(record.extra)

        # If there was an exception, include the traceback
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry)


def setup_logging(config: Config) -> None:
    """Call once at startup. Sets up console + file logging for the whole app."""

    formatter = JSONFormatter()

    # Console handler — prints to terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # File handler — writes to logs/honeypot.jsonl
    # Max 10 MB per file, keeps last 5 files before deleting old ones
    log_file = config.log_dir / "honeypot.jsonl"
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    # Apply both handlers to the root logger
    # Every logger in the app inherits from root, so this covers everything
    root_logger = logging.getLogger()
    root_logger.setLevel(config.log_level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Shortcut used by every module: logger = get_logger(__name__)"""
    return logging.getLogger(name)
