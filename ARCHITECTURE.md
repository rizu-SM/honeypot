# HoneyTrap — Architecture

## Overview

HoneyTrap is a multi-protocol honeypot system that listens on SSH, HTTP, FTP, and Telnet ports,
captures attacker behaviour, enriches it with GeoIP data, and presents everything in a live web dashboard.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            INTERNET / ATTACKER                          │
└───────┬──────────────┬──────────────┬──────────────┬────────────────────┘
        │ :2222        │ :8080        │ :2121        │ :2323
        ▼              ▼              ▼              ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│    SSH    │  │   HTTP    │  │    FTP    │  │  Telnet   │
│ Honeypot  │  │ Honeypot  │  │ Honeypot  │  │ Honeypot  │
│(paramiko) │  │  (Flask)  │  │(socketsrv)│  │  (socket) │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │               │               │               │
      └───────────────┴───────────────┴───────────────┘
                              │
                    event_bus.publish(event)   ← non-blocking put_nowait
                              │
                              ▼
                    ┌──────────────────┐
                    │    EventBus      │  daemon thread, queue.Queue(1000)
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      ┌──────────────┐  ┌─────────┐  ┌───────────────┐
      │  db.insert   │  │  GeoIP  │  │    Discord    │
      │   _event()   │  │ enrich  │  │    Alerter    │
      │  (SQLite WAL)│  │ _async()│  │  (webhook)    │
      └──────────────┘  └────┬────┘  └───────────────┘
                             │
                    ThreadPoolExecutor
                             │
                    ip-api.com (free)
                             │
                    db.update_geo(id, data)
                             │
                             ▼
                    ┌──────────────────┐
                    │   SQLite DB      │  WAL mode, per-thread connections
                    │   honeypot.db    │  PRAGMA busy_timeout=5000
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Dashboard      │  Flask on :5000
                    │   (Flask)        │  polls DB every 5s
                    └──────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
       /api/stats      /api/events    /api/attacks/map
       (Chart.js)    (events table)   (Leaflet.js map)
```

---

## Layers

### 1. Core (`honeypot/core/`)

| File | Responsibility |
|------|----------------|
| `config.py` | Loads `.env` into a typed `@dataclass`. Creates `data/` and `logs/` dirs on startup. |
| `database.py` | SQLite wrapper. Per-thread connections via `threading.local()`. WAL mode. Methods: `insert_event`, `update_geo`, `get_stats`, `get_events`, `get_map_data`. |
| `logger.py` | `JSONFormatter` that emits one JSON object per line. `RotatingFileHandler` (10 MB × 5 backups) + `StreamHandler`. |
| `event_bus.py` | `queue.Queue(maxsize=1000)` with a single daemon worker thread. Fans out to all subscribers. Never blocks the caller. |

### 2. Services (`honeypot/services/`)

| File | Protocol | Port | Technique |
|------|----------|------|-----------|
| `base.py` | — | — | `BaseService` with `start()` / `stop()` threading pattern |
| `ssh_honeypot.py` | SSH | 2222 | `paramiko.ServerInterface` + `Transport`. Always accepts auth. Fake interactive shell with canned responses. |
| `http_honeypot.py` | HTTP | 8080 | Flask app. Serves fake `.env`, `wp-login.php`, admin panels. Sets `Server: Apache` headers. |
| `ftp_honeypot.py` | FTP | 2121 | `socketserver.ThreadingTCPServer`. Handles `USER` / `PASS` / `QUIT` commands. |
| `telnet_honeypot.py` | Telnet | 2323 | Raw socket. Strips IAC negotiation bytes. Fake login prompt. |

### 3. Intelligence (`honeypot/intelligence/`)

| File | Purpose |
|------|---------|
| `geoip.py` | Async GeoIP enrichment via ip-api.com. In-process dict cache (1024 entries). Rate-limited to 45 req/min. Skips RFC-1918 private IPs. |
| `threat_intel.py` | AbuseIPDB reputation check. No-op if API key not set. LRU cache to avoid repeat calls. |

### 4. Alerts (`honeypot/alerts/`)

| File | Purpose |
|------|---------|
| `discord_alert.py` | Sends a Discord embed when attack count crosses a configurable threshold. Thread-safe counter. |

### 5. Dashboard (`honeypot/dashboard/`)

| File | Purpose |
|------|---------|
| `app.py` | Flask app factory. Registers blueprint. Page routes: `/`, `/map`, `/events`. |
| `api.py` | REST blueprint at `/api`. Endpoints: `GET /stats`, `GET /events`, `GET /attacks/map`, `GET /live`. |
| `templates/` | `base.html` (Bootstrap 5 dark), `index.html` (stats + charts), `map.html` (Leaflet), `events.html` (table). |

---

## Database Schema

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    protocol    TEXT    NOT NULL,          -- SSH | HTTP | FTP | TELNET
    source_ip   TEXT    NOT NULL,
    source_port INTEGER,
    username    TEXT,
    password    TEXT,
    commands    TEXT,                      -- JSON array
    method      TEXT,                      -- HTTP only
    path        TEXT,                      -- HTTP only
    user_agent  TEXT,
    headers     TEXT,                      -- JSON object
    body        TEXT,
    country     TEXT,                      -- filled async by GeoIP
    city        TEXT,
    isp         TEXT,
    latitude    REAL,
    longitude   REAL,
    abuse_score INTEGER                    -- filled async by ThreatIntel
);

CREATE INDEX idx_events_ip        ON events(source_ip);
CREATE INDEX idx_events_protocol  ON events(protocol);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_country   ON events(country);
```

---

## Threading Model

```
Main Thread
  ├── EventBus daemon thread          (1 thread)
  ├── SSHHoneypot thread              (1 listener + N per-connection threads)
  ├── HTTPHoneypot thread             (Flask internal thread pool)
  ├── FTPHoneypot thread              (socketserver + N handler threads)
  ├── TelnetHoneypot thread           (1 listener + N per-connection threads)
  ├── Dashboard thread                (Flask internal thread pool)
  └── GeoIP ThreadPoolExecutor        (2 worker threads)
```

Each honeypot service runs in its own daemon thread. Connections are handled in short-lived
child threads. All cross-thread communication goes through `EventBus.publish()` which is
the only shared mutable state besides SQLite.

---

## Key Design Decisions

| Decision | Reason |
|----------|--------|
| SQLite over Postgres/Elasticsearch | Zero external dependencies. WAL mode handles concurrent writes. Enough for honeypot data volumes. |
| EventBus with `put_nowait` | Honeypot threads must never block on DB I/O. If the bus is full, the event is dropped — availability beats completeness. |
| GeoIP enrichment is async | A network lookup (≥50ms) must not stall the event bus. The DB row is written first with no geo, then patched via `UPDATE WHERE id=?`. |
| paramiko always accepts auth | Maximises command capture. Attackers who expect rejection move on; accepting them yields more intelligence. |
| 4 prod dependencies only | `paramiko`, `flask`, `requests`, `python-dotenv`. Everything else is stdlib. Easy audit, easy Docker layer caching. |
| High port numbers (2222, 8080…) | Avoids root privileges on Linux and UAC prompts on Windows during development. |
