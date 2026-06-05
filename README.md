# HoneyTrap 🍯

A multi-protocol honeypot system built in Python that captures SSH, HTTP, FTP, and Telnet attack attempts. SSH attackers land in a realistic fake Linux shell with a stateful filesystem, pipe support, and 40+ simulated commands. All interactions are enriched with GeoIP data, stored in SQLite, and displayed in a live web dashboard with Discord alerts.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What it does

HoneyTrap listens on multiple ports pretending to be a real server. When attackers connect and attempt to log in or probe for vulnerabilities, every interaction is captured, enriched with geographic data, stored in a database, and displayed in a real-time dashboard.

```
Attacker (SSH / FTP / HTTP / Telnet)
         ↓
  HoneyTrap captures credentials, commands, requests
         ↓
  GeoIP enrichment  →  country, city, ISP, coordinates
         ↓
  SQLite database  +  Live dashboard  +  Discord alerts
```

---

## Features

- **4 protocol honeypots** running concurrently as threads
  - SSH — credentials + every command captured in a full fake Linux shell
  - HTTP — requests to fake `.env`, WordPress login, admin panels
  - FTP — login attempts
  - Telnet — login attempts
- **Realistic fake shell** — stateful in-memory Linux filesystem per SSH session; 40+ commands, pipe (`ls | grep`), output redirect (`echo x > file`), dynamic prompt (`root@ubuntu:/etc#`)
- **Real-time web dashboard** with stat cards, charts, and live event table
- **Attack map** — world map showing attacker locations (Leaflet.js)
- **GeoIP enrichment** — async lookup via ip-api.com (free, no key needed)
- **Discord alerts** — webhook notification at configurable attack threshold
- **REST API** — query stats and events programmatically
- **Docker deployment** — one command to run anywhere
- **Structured JSON logging** — rotating log files, machine-readable

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   ATTACKERS                      │
└───┬──────────┬──────────┬──────────┬────────────┘
    │:2222     │:8080     │:2121     │:2323
    ▼          ▼          ▼          ▼
  SSH        HTTP        FTP      Telnet
  Honeypot   Honeypot   Honeypot  Honeypot
    │          │          │          │
    └──────────┴──────────┴──────────┘
                    │
              EventBus (queue)
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
   SQLite DB    GeoIP lookup  Discord alert
       │
       ▼
   Dashboard :5000
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document.

---

## Quick Start

**Without Docker:**
```bash
git clone https://github.com/rizu-SM/honeypot.git
cd honeypot
pip install -r requirements.txt
cp .env.example .env
python main.py
```

**With Docker:**
```bash
git clone https://github.com/rizu-SM/honeypot.git
cd honeypot
cp .env.example .env
docker-compose up --build
```

Open the dashboard: **http://localhost:5000**

---

## Configuration

Copy `.env.example` to `.env` and edit as needed:

| Variable | Default | Description |
|---|---|---|
| `SSH_PORT` | `2222` | SSH honeypot port |
| `HTTP_PORT` | `8080` | HTTP honeypot port |
| `FTP_PORT` | `2121` | FTP honeypot port |
| `TELNET_PORT` | `2323` | Telnet honeypot port |
| `DASHBOARD_PORT` | `5000` | Web dashboard port |
| `DISCORD_WEBHOOK_URL` | _(empty)_ | Discord webhook for alerts (optional) |
| `DISCORD_ALERT_THRESHOLD` | `10` | Send alert every N attacks |
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB reputation check (optional) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Dashboard

| Page | URL | Description |
|---|---|---|
| Overview | `/` | Stat cards, charts, live event table |
| Attack Map | `/map` | World map with attack origin markers |
| Events | `/events` | Filterable paginated event history |

**REST API:**
```
GET /api/stats          — summary statistics
GET /api/events         — paginated event list
GET /api/attacks/map    — geo coordinates for map
GET /api/live           — last 20 events (polled every 5s)
```

---

## Project Structure

```
honeypot/
├── main.py                    # Entry point
├── honeypot/
│   ├── core/                  # Config, database, logger, event bus
│   ├── services/              # SSH, HTTP, FTP, Telnet honeypots
│   ├── deception/             # Fake shell: filesystem, 40+ commands, pipe/redirect
│   ├── intelligence/          # GeoIP enrichment
│   ├── alerts/                # Discord notifications
│   └── dashboard/             # Flask web UI + REST API
├── docs/                      # Per-module documentation
├── static/                    # CSS and JS assets
├── tests/                     # Test suite
├── Dockerfile
├── docker-compose.yml
└── ARCHITECTURE.md
```

---

## Technical Highlights

- **Custom SSH server** using paramiko's `ServerInterface` and `Transport` — handles banner negotiation, auth, interactive shell sessions, and exec requests
- **Deception layer** — in-memory fake Linux filesystem (`deepcopy` per session), 40+ simulated commands, pipe chaining (`cmd1 | cmd2`), output redirect (`> file`), and a dynamic shell prompt that updates as the attacker navigates
- **Event-driven architecture** with a thread-safe `queue.Queue` dispatcher — honeypot threads never block on I/O
- **Async GeoIP enrichment** via `ThreadPoolExecutor` — events are saved immediately, geo data is patched in the background
- **SQLite WAL mode** with per-thread connections — concurrent writes from 4 services without locks or contention
- **4 production dependencies** — `paramiko`, `flask`, `requests`, `python-dotenv`. Everything else is Python stdlib

---

## Security & Ethics

This tool is for **authorized security research and learning only**.

- Deploy only on systems you own or have explicit permission to monitor
- Captured credentials are for threat intelligence analysis only
- Do not expose the dashboard publicly without authentication
- Check local laws before deploying honeypots in production environments

---

## License

MIT License — see [LICENSE](LICENSE) for details.
