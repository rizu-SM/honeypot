# database.py

## Purpose
Permanently stores every attack event captured by the honeypot services.
Provides query methods the dashboard uses to show statistics and event history.


## Key concepts

### WAL mode (Write-Ahead Log)
Normally SQLite locks the whole file during a write — all readers must wait.
WAL mode changes this: writers write to a separate log file first, readers
can still read the main database at the same time.

This matters because SSH, FTP, HTTP, and Telnet all write simultaneously.

```python
conn.execute("PRAGMA journal_mode=WAL")
```

### threading.local()
SQLite connections cannot be safely shared between threads.
`threading.local()` gives each thread its own private storage slot.
Each thread gets its own connection, created on first use.

```
SSH thread    → _local.conn = Connection A  → writes safely
FTP thread    → _local.conn = Connection B  → writes safely (same moment)
Telnet thread → _local.conn = Connection C  → writes safely (same moment)
```

### sqlite3.Row
By default SQLite returns plain tuples: `(1, "SSH", "1.2.3.4")`
Setting `row_factory = sqlite3.Row` makes rows behave like dicts:
```python
row["protocol"]    # "SSH"
row["source_ip"]   # "1.2.3.4"
dict(row)          # converts to plain dict for JSON serialization
```

### busy_timeout
If two threads try to write at the exact same millisecond, one must wait.
`PRAGMA busy_timeout=5000` tells SQLite to retry for up to 5 seconds before
giving up, instead of failing immediately.

## Two-phase write design
Attack events are saved in two steps:

**Step 1 — insert_event()** — runs immediately when attack arrives (fast):
```
row saved: ip=1.2.3.4, protocol=SSH, username=root, password=123 | country=NULL
```

**Step 2 — update_geo()** — runs later after GeoIP lookup completes (~100ms):
```
row updated: country=China, city=Beijing, latitude=39.9, longitude=116.4
```

This means the honeypot never waits for a network call before saving.

## Methods summary

| Method | Used by | Returns |
|---|---|---|
| `insert_event(event)` | EventBus subscriber | new row ID |
| `update_geo(id, geo)` | GeoIP service | nothing |
| `get_events(page, ...)` | Dashboard /api/events | paginated list |
| `get_stats()` | Dashboard /api/stats | summary counts |
| `get_map_data()` | Dashboard /api/attacks/map | geo points |

## Schema
```sql
events (
    id, timestamp, protocol, source_ip, source_port,
    username, password, commands,      -- attack credentials
    method, path, user_agent, headers, body,  -- HTTP only
    country, city, isp, latitude, longitude,  -- filled by GeoIP
    abuse_score                               -- filled by ThreatIntel
)
```
`commands` and `headers` are stored as JSON strings because SQLite has no
array or object type.

## Flow
```
Attack arrives
    ↓
insert_event()  →  row saved immediately (no geo)
    ↓
[background thread]
GeoIP lookup → update_geo()  →  row patched with location
    ↓
Dashboard queries get_stats() / get_events() / get_map_data()
```
