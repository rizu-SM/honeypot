import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from honeypot.core.logger import get_logger

logger = get_logger(__name__)


class GeoIPService:
    """
    Looks up the geographic location of an IP address using ip-api.com (free).
    Results are cached in memory so the same IP is never looked up twice.
    Lookups run in a background thread pool — never blocks the caller.
    """

    def __init__(self, config, db):
        self.db = db
        self._cache: dict = {}                    # ip → geo data
        self._cache_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="GeoIP"
        )
        # ip-api.com free tier allows 45 requests per minute
        self._rate_limit  = 45
        self._interval    = 60.0 / self._rate_limit   # seconds between calls
        self._last_call   = 0.0
        self._rate_lock   = threading.Lock()

    def enrich_async(self, event_id: int, ip: str) -> None:
        """
        Submit a GeoIP lookup to the background thread pool.
        Returns immediately — caller never waits.
        """
        if self._is_private(ip):
            return   # private IPs (192.168.x.x etc.) have no geo data

        self._executor.submit(self._enrich_worker, event_id, ip)

    def _enrich_worker(self, event_id: int, ip: str) -> None:
        """Runs in background thread — looks up IP and patches the DB row."""
        geo = self._lookup(ip)
        if geo:
            self.db.update_geo(event_id, geo)
            logger.info("GeoIP enriched", extra={"extra": {
                "ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
            }})

    def _lookup(self, ip: str) -> dict | None:
        """Check cache first. If miss, call the API."""
        # Cache hit — return immediately
        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]

        # Cache miss — call the API
        geo = self._fetch(ip)

        # Store result (even None, so we don't retry failed lookups)
        with self._cache_lock:
            self._cache[ip] = geo

        return geo

    def _fetch(self, ip: str) -> dict | None:
        """Call ip-api.com and return parsed geo data."""
        self._rate_wait()   # respect the 45 req/min limit
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,isp,lat,lon"},
                timeout=5,
            )
            data = response.json()

            if data.get("status") == "success":
                return {
                    "country":   data["country"],
                    "city":      data["city"],
                    "isp":       data["isp"],
                    "latitude":  data["lat"],
                    "longitude": data["lon"],
                }
        except Exception:
            logger.exception("GeoIP lookup failed", extra={"extra": {"ip": ip}})

        return None

    def _rate_wait(self) -> None:
        """Ensure we don't exceed 45 requests per minute."""
        with self._rate_lock:
            now  = time.monotonic()
            wait = self._interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def _is_private(self, ip: str) -> bool:
        """Returns True for private/loopback IPs that have no geo data."""
        try:
            addr = ipaddress.ip_address(ip)
            return (
                addr.is_private or
                addr.is_loopback or
                addr.is_reserved or
                addr.is_multicast
            )
        except ValueError:
            return True

    @property
    def cache_size(self) -> int:
        """How many IPs are currently cached."""
        return len(self._cache)
