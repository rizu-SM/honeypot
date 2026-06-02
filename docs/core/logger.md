# logger.py

## Purpose
Sets up logging for the entire application — writes structured JSON logs to
both the terminal and a rotating log file. Every module uses this to record
what is happening inside the system.

## What it is NOT
`logger.py` does NOT store attack data. It is a developer tool — for errors,
warnings, and status messages like "service started" or "database ready".
Attack data is stored in `database.py`.

## Why JSON logs?
Plain text logs:
```
2024-01-01 12:00:00 INFO SSH connection from 1.2.3.4
```
JSON logs:
```json
{"timestamp": "2024-01-01T12:00:00Z", "level": "INFO", "message": "SSH connection", "ip": "1.2.3.4"}
```
JSON is machine-readable — you can filter, search, and parse it with scripts.

## Key concepts

### Python logging hierarchy
Python's logging is a tree:
```
root logger
  └── honeypot
        ├── honeypot.core
        │     ├── honeypot.core.config
        │     └── honeypot.core.database
        └── honeypot.services
              └── honeypot.services.ssh
```
By setting handlers on the root logger, every child logger in the whole app
inherits them automatically. One setup call covers everything.

### JSONFormatter
Overrides Python's default formatter. Every log record becomes a JSON object:
```python
entry = {
    "timestamp": "...",
    "level": "INFO",
    "logger": "honeypot.services.ssh",
    "message": "New connection",
}
```
If `extra={"extra": {"ip": "1.2.3.4"}}` is passed, those fields are merged in.
If an exception was logged, the traceback is included as a string.

### RotatingFileHandler
Writes to `logs/honeypot.jsonl`.
When the file hits 10 MB it rolls over to a new file.
Keeps the last 5 files, deletes older ones.
Prevents the log file from growing forever.

### StreamHandler
Prints log output to the terminal so you can watch events in real time.

## How modules use it
```python
from honeypot.core.logger import get_logger

logger = get_logger(__name__)   # __name__ = "honeypot.services.ssh"

logger.info("Connection received")
logger.info("Details", extra={"extra": {"ip": "1.2.3.4", "port": 2222}})
logger.exception("Something broke")   # includes full traceback
```

## Setup — called once in main.py
```python
setup_logging(config)   # after this, all loggers work everywhere
```

## Flow
```
logger.info("message", extra={...})
    ↓
JSONFormatter.format()  →  builds dict  →  json.dumps()  →  one-line string
    ↓              ↓
StreamHandler      RotatingFileHandler
(terminal)         (logs/honeypot.jsonl)
```
