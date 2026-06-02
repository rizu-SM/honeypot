# base.py

## Purpose
A parent class that every honeypot service inherits from.
Contains the shared logic: threading, graceful shutdown, error handling,
and event emitting. Each service only implements `_run()`.

## Why it exists
Without BaseService, SSH, FTP, HTTP, and Telnet would each repeat:
- Create a thread
- Handle the stop signal
- Catch unhandled exceptions
- Build the event dict and publish it

That is 4x duplicated code. BaseService writes it once and shares it.

## Key concepts

### Inheritance
```python
class FTPHoneypot(BaseService):   # FTPHoneypot inherits everything from BaseService
    def _run(self):
        ...                       # only this needs to be written
```
FTPHoneypot automatically gets `start()`, `stop()`, `_emit()` for free.

### threading.Event — the stop signal
A simple boolean flag shared between threads:
```python
self._stop_event = threading.Event()

# main thread calls:
service.stop()              # sets the flag to True

# service thread checks:
while not self._stop_event.is_set():
    ...                     # exits the loop when flag is True
```
This is called "cooperative shutdown" — the service checks the flag
itself and exits cleanly, rather than being killed forcefully.

### daemon=True
The service thread is a daemon. When main.py exits, Python kills all
daemon threads automatically. No manual cleanup needed.

### _safe_run()
Wraps `_run()` in a try/except. If an unhandled exception occurs inside
a service (e.g. a bug in SSH handling), the error is logged but the
other services keep running. Without this, one crash would silently
kill that thread with no error message.

### _emit(**kwargs)
Helper that every service calls when it captures an attacker interaction:
```python
self._emit(
    protocol="FTP",
    source_ip="1.2.3.4",
    source_port=54321,
    username="admin",
    password="admin123",
)
```
`_emit` adds the timestamp automatically and passes the dict to the EventBus.

## How a service uses it
```python
class FTPHoneypot(BaseService):
    def _run(self):
        # set up socket, listen for connections...
        while not self._stop_event.is_set():
            # accept connection
            # capture credentials
            self._emit(protocol="FTP", source_ip=ip, username=user, password=pw)
```

## Flow
```
main.py
    ↓
service = FTPHoneypot(config, event_bus)
service.start()
    ↓
BaseService.start()
    → creates thread → calls _safe_run() → calls FTPHoneypot._run()
    ↓
FTPHoneypot._run() runs forever in background thread
    → attacker connects
    → self._emit(...)  → event_bus.publish(event)
    ↓
main.py calls service.stop()
    → _stop_event.set()
    → _run() loop exits on next iteration
```
