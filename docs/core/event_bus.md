# event_bus.py

## Purpose
Connects honeypot services (producers) to database/alerts (consumers) without
coupling them together. Services never wait for slow operations like database
writes or GeoIP lookups — they drop the event and move on immediately.

## The problem it solves
Without EventBus — the naive approach:
```python
# Inside SSH handler — BAD
db.insert_event(event)        # wait ~1ms
geoip.lookup(event["ip"])     # wait ~100ms  ← attacker is waiting!
discord.send_alert(event)     # wait ~200ms  ← attacker still waiting!
```
The attacker's connection is blocked while we do slow work.

With EventBus:
```python
# Inside SSH handler — GOOD
bus.publish(event)   # drops into queue, returns in microseconds
```
All the slow work happens in a background thread. The attacker never waits.

## Key concepts

### queue.Queue
Python's built-in thread-safe queue. One thread puts items in (producers),
another thread takes them out (consumer). They never conflict or corrupt data.

```
SSH thread  →  |  event  event  event  |  →  EventBus worker thread
FTP thread  →  |       (queue)         |
```
`maxsize=1000` — if the worker falls behind and 1000 events pile up,
new ones are dropped rather than crashing or using unlimited memory.

### put_nowait() vs put()
- `put()` — waits if the queue is full (blocks the caller)
- `put_nowait()` — raises `queue.Full` immediately if full

We use `put_nowait()` so honeypot threads NEVER block.

### daemon=True
The worker thread is a daemon. When the main program exits, Python
automatically kills all daemon threads. No cleanup code needed.

### _dispatch_loop()
Runs forever in the background thread.
`queue.get()` pauses the thread (uses zero CPU) until an event arrives.
The moment `publish()` adds an event, `get()` wakes up instantly.

## Line by line

```python
self._queue.get()          # sleep until an event arrives
for handler in self._subscribers:
    handler(event)         # call db.insert_event(event)
                           # call discord.handle(event)
self._queue.task_done()    # mark item as processed
```

The `try/except` around each handler ensures one broken subscriber
(e.g. database error) does not stop the others (e.g. Discord alert).

## How it's wired up in main.py
```python
bus = EventBus()
bus.subscribe(db.insert_event)     # every event → saved to database
bus.subscribe(discord.handle)      # every event → check alert threshold
bus.start()                        # start background thread
```

## Flow
```
[SSH / FTP / HTTP / Telnet threads]
          |
          | bus.publish(event)   ← non-blocking, microseconds
          ↓
    [queue.Queue]
    event | event | event
          ↓
    [EventBus worker thread]  ← single background thread
          |
          ├──→ db.insert_event(event)
          ├──→ geoip.enrich_async(event)
          └──→ discord.handle(event)
```

## Analogy
Think of a post office drop box:
- You (honeypot thread) drop a letter in the slot and walk away immediately
- The postal worker (EventBus thread) picks it up and delivers it to each address
- You never wait for the letter to be delivered
