# telnet_honeypot.py

## Purpose
Emulates a Telnet login prompt to capture credentials from attackers
targeting old routers, IoT devices, and industrial systems that still
run Telnet instead of SSH.

## How the Telnet protocol works
Telnet is plain text — no encryption, no handshake complexity:

```
Server → "\r\nUbuntu 20.04.6 LTS\r\n\r\nlogin: "
Client → "root"
Server → "\r\nPassword: "
Client → "toor"
Server → "\r\nLogin incorrect\r\n"    ← we always reject (realistic)
```

We show "Login incorrect" instead of accepting — this is more realistic
for a login prompt. The credentials are already captured before we respond.

## Key concepts

### IAC bytes (the tricky part)
Telnet clients don't just send text. They also send control sequences
starting with byte 0xFF (called IAC — "Interpret As Command"):

```
Raw bytes from client:  "r o o t \xFF \xFB \x01 \r \n"
After strip_iac():      "r o o t \r \n"
Decoded:                "root"
```

Without stripping, the username field would contain garbage characters.

### strip_iac() — how it works
Walks through the bytes one by one:
```
byte == 0xFF (IAC)?
  → next byte is WILL/WONT/DO/DONT (0xFB-0xFE)?  → skip 3 bytes
  → otherwise                                     → skip 2 bytes
normal byte?
  → keep it
```

### Raw socket vs socketserver
Unlike FTP (which used socketserver), Telnet uses raw `socket` directly.
This shows both approaches. The pattern is:
```python
server_sock.settimeout(1.0)     # don't block forever on accept()
while not self._stop_event.is_set():
    client_sock, addr = server_sock.accept()   # wait 1 second
    threading.Thread(target=self._handle_client, ...).start()
```
`settimeout(1.0)` raises `socket.timeout` every second if no connection
arrives — we catch it, check the stop flag, and loop again.

### Reading one byte at a time
`_read_line()` reads 1 byte at a time until it sees `\r` or `\n`.
Why not `readline()`? Because raw sockets don't buffer lines — we have
to build the line ourselves byte by byte.

### sock.settimeout(30) on client socket
If an attacker connects but does nothing, we don't want to hold the
thread open forever. 30 second timeout auto-disconnects idle clients.

## Why "Login incorrect"?
Showing a fake shell after login would be more engaging but also more
complex. "Login incorrect" is simpler and still realistic — most real
Telnet servers don't accept root login anyway. The credentials are
captured before the response is sent, so it doesn't matter.

## What we capture
```python
{
    "timestamp":   "2024-01-01T12:00:00Z",
    "protocol":    "Telnet",
    "source_ip":   "45.33.32.156",
    "source_port": 54321,
    "username":    "root",
    "password":    "toor",
}
```

## Flow
```
Attacker connects on port 2323
    ↓
server_sock.accept() returns client socket + address
    ↓
New thread → _handle_client(sock, addr)
    ↓
Send banner + "login: "
Read username  (strip_iac → decode → strip whitespace)
Send "Password: "
Read password  (strip_iac → decode → strip whitespace)
    ↓
event_bus.publish({protocol: Telnet, ip, username, password})
    ↓
Send "Login incorrect"
Close socket
```
