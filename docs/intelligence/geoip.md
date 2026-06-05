# geoip.py

## Purpose
Enriches attack events with geographic location data — country, city, ISP,
latitude and longitude. This powers the attack map on the dashboard.

## Why async?
A GeoIP lookup is a network call (~50-200ms). If we did it inside the
honeypot thread, every attacker connection would be delayed by that wait.

Solution: save the event immediately with no geo data, then patch it later:
```
attack arrives → db.insert_event() → row saved (country=NULL)
                      ↓
              geoip.enrich_async()  → background thread → ip-api.com
                                           ↓
                                    db.update_geo()  → row patched
```

## API used — ip-api.com
Free, no API key needed. Rate limit: 45 requests/minute.
```
GET http://ip-api.com/json/45.33.32.156?fields=status,country,city,isp,lat,lon

Response:
{
  "status": "success",
  "country": "United States",
  "city": "Fremont",
  "isp": "Linode",
  "lat": 37.5483,
  "lon": -121.9886
}
```

## Key concepts

### Dict cache
Every lookup result is stored in `self._cache`:
```python
self._cache = {
    "45.33.32.156": {"country": "US", "city": "Fremont", ...},
    "1.2.3.4":      {"country": "China", "city": "Beijing", ...},
}
```
Same IP attacks twice → second lookup returns from cache instantly, no API call.
We even cache `None` (failed lookups) so we don't retry the same broken IP.

### threading.Lock on cache
Two background threads could try to write to the cache at the same time.
A `Lock` ensures only one thread writes at a time:
```python
with self._cache_lock:
    self._cache[ip] = geo    # only one thread can be here at once
```

### ThreadPoolExecutor
A pool of 2 reusable worker threads. We submit tasks to it:
```python
self._executor.submit(self._enrich_worker, event_id, ip)
```
`submit()` returns immediately. The work runs in the background.
No need to create/destroy threads manually.

### Rate limiting (_rate_wait)
ip-api.com allows 45 requests per minute = 1 request every 1.33 seconds.
Before each API call, we check how long since the last call and sleep the difference:
```python
wait = 1.33 - (now - last_call)
if wait > 0:
    time.sleep(wait)
```

### _is_private()
Private IP ranges (192.168.x.x, 10.x.x.x, 127.x.x.x) are internal network
addresses — they have no geo data. We skip the API call for these entirely.
The `ipaddress` module (stdlib) handles all the range checks.

## Flow
```
event_bus delivers event
    ↓
geoip.enrich_async(event_id, "45.33.32.156")
    ↓
_is_private()? → No → executor.submit(_enrich_worker)
    ↓                        returns immediately
[background thread]
    ↓
_lookup("45.33.32.156")
    ↓
cache hit? → return cached data
cache miss? → _rate_wait() → requests.get(ip-api.com) → cache result
    ↓
db.update_geo(event_id, {country, city, isp, lat, lon})
```
