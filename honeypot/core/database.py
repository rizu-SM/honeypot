import json
import sqlite3
import threading
from pathlib import Path

from honeypot.core.logger import get_logger

logger = get_logger(__name__)

# Each thread gets its own SQLite connection stored here
_local = threading.local()


class Database:
    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._init_schema()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it if needed."""
        if not hasattr(_local, "conn") or _local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row   # rows behave like dicts
            conn.execute("PRAGMA journal_mode=WAL")   # allow concurrent reads + writes
            conn.execute("PRAGMA synchronous=NORMAL") # safe with WAL, faster than FULL
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")  # retry for 5s on lock contention
            _local.conn = conn
        return _local.conn

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create the events table and indexes if they don't exist yet."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                protocol    TEXT    NOT NULL,
                source_ip   TEXT    NOT NULL,
                source_port INTEGER,
                username    TEXT,
                password    TEXT,
                commands    TEXT,       -- JSON array of strings
                method      TEXT,       -- HTTP only: GET, POST, etc.
                path        TEXT,       -- HTTP only: /wp-login.php etc.
                user_agent  TEXT,
                headers     TEXT,       -- JSON object
                body        TEXT,
                country     TEXT,       -- filled later by GeoIP
                city        TEXT,
                isp         TEXT,
                latitude    REAL,
                longitude   REAL,
                abuse_score INTEGER     -- filled later by ThreatIntel
            );

            CREATE INDEX IF NOT EXISTS idx_ip        ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_protocol  ON events(protocol);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_country   ON events(country);
        """)
        conn.commit()
        logger.info("Database ready", extra={"extra": {"path": self.db_path}})

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def insert_event(self, event: dict) -> int:
        """Save one attack event. Returns the new row ID."""
        conn = self._get_conn()
        cursor = conn.execute("""
            INSERT INTO events (
                timestamp, protocol, source_ip, source_port,
                username, password, commands,
                method, path, user_agent, headers, body
            ) VALUES (
                :timestamp, :protocol, :source_ip, :source_port,
                :username, :password, :commands,
                :method, :path, :user_agent, :headers, :body
            )
        """, {
            "timestamp":   event.get("timestamp"),
            "protocol":    event.get("protocol"),
            "source_ip":   event.get("source_ip"),
            "source_port": event.get("source_port"),
            "username":    event.get("username"),
            "password":    event.get("password"),
            "commands":    json.dumps(event.get("commands")) if event.get("commands") else None,
            "method":      event.get("method"),
            "path":        event.get("path"),
            "user_agent":  event.get("user_agent"),
            "headers":     json.dumps(event.get("headers")) if event.get("headers") else None,
            "body":        event.get("body"),
        })
        conn.commit()
        return cursor.lastrowid

    def update_geo(self, event_id: int, geo: dict) -> None:
        """Patch geo fields onto an existing event row (called async after GeoIP lookup)."""
        conn = self._get_conn()
        conn.execute("""
            UPDATE events
            SET country=:country, city=:city, isp=:isp,
                latitude=:latitude, longitude=:longitude
            WHERE id=:id
        """, {
            "country":   geo.get("country"),
            "city":      geo.get("city"),
            "isp":       geo.get("isp"),
            "latitude":  geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "id":        event_id,
        })
        conn.commit()

    # ------------------------------------------------------------------
    # Reads — used by the dashboard
    # ------------------------------------------------------------------

    def get_events(self, page: int = 1, per_page: int = 50,
                   protocol: str = None, country: str = None) -> dict:
        """Return a paginated list of events, newest first."""
        conn = self._get_conn()

        where, params = [], {}
        if protocol:
            where.append("protocol = :protocol")
            params["protocol"] = protocol
        if country:
            where.append("country = :country")
            params["country"] = country

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM events {where_sql}", params
        ).fetchone()[0]

        params["limit"]  = per_page
        params["offset"] = (page - 1) * per_page

        rows = conn.execute(
            f"SELECT * FROM events {where_sql} ORDER BY id DESC LIMIT :limit OFFSET :offset",
            params
        ).fetchall()

        return {
            "events": [dict(r) for r in rows],
            "total":  total,
            "page":   page,
            "pages":  max(1, (total + per_page - 1) // per_page),
        }

    def get_stats(self) -> dict:
        """Return summary numbers for the dashboard."""
        conn = self._get_conn()

        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        last_24h = conn.execute("""
            SELECT COUNT(*) FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
        """).fetchone()[0]

        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM events"
        ).fetchone()[0]

        top_protocols = conn.execute("""
            SELECT protocol, COUNT(*) as count
            FROM events GROUP BY protocol ORDER BY count DESC LIMIT 5
        """).fetchall()

        top_countries = conn.execute("""
            SELECT country, COUNT(*) as count
            FROM events WHERE country IS NOT NULL
            GROUP BY country ORDER BY count DESC LIMIT 10
        """).fetchall()

        top_ips = conn.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM events GROUP BY source_ip ORDER BY count DESC LIMIT 10
        """).fetchall()

        attacks_by_hour = conn.execute("""
            SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                   COUNT(*) as count
            FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour ASC
        """).fetchall()

        return {
            "total":            total,
            "last_24h":         last_24h,
            "unique_ips":       unique_ips,
            "top_protocols":    [dict(r) for r in top_protocols],
            "top_countries":    [dict(r) for r in top_countries],
            "top_ips":          [dict(r) for r in top_ips],
            "attacks_by_hour":  [dict(r) for r in attacks_by_hour],
        }

    def get_map_data(self) -> list:
        """Return geo points for the attack map — one row per unique location."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT latitude, longitude, country, COUNT(*) as count
            FROM events
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            GROUP BY latitude, longitude, country
            ORDER BY count DESC
        """).fetchall()
        return [dict(r) for r in rows]
