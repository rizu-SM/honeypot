# ftp_honeypot.py

## Purpose
Emulates an FTP server to capture login credentials from attackers
scanning for open FTP ports and trying default username/password combinations.

## How the FTP protocol works
FTP is plain text — commands and responses are just strings:

```
Server → "220 FTP server ready"       ← we send this first (banner)
Client → "USER admin"                  ← attacker sends username
Server → "331 Please enter password"
Client → "PASS admin123"               ← attacker sends password
Server → "230 Login successful"        ← we always accept
Client → "QUIT"
Server → "221 Goodbye"
```

We always respond with "230 Login successful" — this keeps attackers
engaged and may reveal more commands they try after logging in.

## Key concepts

### socketserver.StreamRequestHandler
Python's built-in handler base class. Gives us two file-like objects:
- `self.rfile` — read from the client (`readline()`)
- `self.wfile` — write to the client (`write()`)

No need to manage raw socket bytes — just read lines and write lines.

### socketserver.ThreadingTCPServer
Handles the boring parts of running a TCP server:
- Binds to the port
- Accepts incoming connections
- Spawns a new thread per connection (so multiple attackers connect simultaneously)

```python
class FTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True   # no "address already in use" on restart
    daemon_threads = True        # threads die when main program exits
```

### Why event_bus is a class attribute
`socketserver` creates handler instances internally — we can't pass
arguments to `FTPHandler.__init__()`. The solution: set `event_bus`
as a class-level attribute before starting the server:
```python
FTPHandler.event_bus = self.event_bus   # done once in FTPHoneypot._run()
```
All handler instances then share it via `self.event_bus`.

### server.timeout = 1.0 + handle_request()
`handle_request()` blocks for up to 1 second waiting for a connection,
then returns. This lets us check `_stop_event.is_set()` every second
for clean shutdown. Without the timeout, the server would block forever.

### \r\n (CRLF)
FTP requires lines to end with `\r\n` (carriage return + newline), not
just `\n`. We always encode responses as `f"{message}\r\n".encode()`.

## What we capture
```python
{
    "timestamp":   "2024-01-01T12:00:00Z",
    "protocol":    "FTP",
    "source_ip":   "45.33.32.156",
    "source_port": 54321,
    "username":    "admin",
    "password":    "admin123",
}
```

## Commands we fake
| Command | Our response | Why |
|---------|-------------|-----|
| USER | 331 | ask for password |
| PASS | 230 | accept, capture credentials |
| QUIT | 221 | goodbye |
| SYST | 215 UNIX | pretend to be Linux |
| PWD  | 257 "/" | pretend to have a root dir |
| LIST | 425 | pretend PASV not set up |
| TYPE | 200 | acknowledge binary mode |
| unknown | 500 | unknown command |

## Flow
```
Attacker connects on port 2121
    ↓
FTPServer spawns new thread → FTPHandler.handle()
    ↓
Send "220 FTP server ready"
    ↓
Read "USER admin"   → send "331 Please enter password"
Read "PASS admin"   → publish event to EventBus → send "230 Login successful"
Read "QUIT"         → send "221 Goodbye" → exit
    ↓
Thread ends, server waits for next connection
```
