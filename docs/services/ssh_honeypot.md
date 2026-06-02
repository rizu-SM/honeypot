# ssh_honeypot.py

## Purpose
Emulates a real SSH server using paramiko. Captures login credentials AND
the commands attackers run after logging in. SSH is the most targeted
service on the internet — bots constantly scan for open port 22/2222.

## How SSH works (simplified)
Unlike FTP/Telnet, SSH is encrypted. The handshake goes:

```
Client → Server : "I want to connect"
Server → Client : "Here is my public key" (RSA host key)
Client           : verifies key, sets up encryption
Client → Server : "USER root, PASS toor"   (auth attempt)
Server → Client : "Welcome"                (we always accept)
Client → Server : types commands
Server → Client : fake shell responses
```

## Key concepts

### paramiko.Transport
Wraps a raw socket and handles ALL the SSH crypto and protocol.
We never deal with encryption ourselves — we just hand it our socket:
```python
transport = paramiko.Transport(client_sock)
transport.add_server_key(host_key)
transport.start_server(server=server_interface)
```
After `start_server()`, paramiko calls our `SSHServerInterface` methods
at the right moments during the handshake.

### paramiko.ServerInterface
A class we override with our own logic. Paramiko calls its methods
during the SSH handshake:

| Method | When paramiko calls it | What we return |
|--------|----------------------|----------------|
| `check_channel_request` | attacker opens a channel | OPEN_SUCCEEDED |
| `check_auth_password` | attacker sends credentials | AUTH_SUCCESSFUL (always) |
| `check_channel_shell_request` | attacker requests a shell | True |
| `check_channel_exec_request` | attacker runs one command | True |

### RSA host key
Every SSH server has a key pair stored on disk. It proves identity.
We generate one on first startup and save it to `data/ssh_host_key`.
On restart, we load the same key — if we generated a new one each time,
SSH clients would show a "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED"
error and refuse to connect.

### threading.Event — shell_ready
`check_auth_password` and `check_channel_shell_request` are called by
paramiko in sequence. We use `shell_ready` as a signal between them:
```
check_auth_password()   → credentials captured
check_channel_shell_request() → shell_ready.set()   ← signal
_handle_client()        → shell_ready.wait(10)       ← waits for signal
→ _run_shell()          ← now we know shell is open
```

### Why always accept auth?
Returning `AUTH_SUCCESSFUL` every time keeps attackers connected.
If we reject them, they move on and we capture only one attempt.
If we accept, they open a shell and we capture every command they run.

### _read_channel — one byte at a time
SSH channels stream bytes, not lines. We read one byte at a time and:
- Stop at `\r` (Enter key)
- Handle `\x7f` (Backspace) — erase last character
- Echo each character back so the attacker sees what they type

### Two events published
1. **SSH** — credentials (username + password) captured at login
2. **SSH_SESSION** — full list of commands captured after login

## What we capture

**At login:**
```python
{"protocol": "SSH", "source_ip": "1.2.3.4", "username": "root", "password": "toor"}
```

**After shell session:**
```python
{"protocol": "SSH_SESSION", "source_ip": "1.2.3.4", "commands": ["id", "whoami", "cat /etc/passwd"]}
```

## Flow
```
Attacker connects on port 2222
    ↓
paramiko.Transport wraps the socket
transport.start_server() → SSH handshake begins
    ↓
check_auth_password("root", "toor")
    → publish SSH event (credentials)
    → return AUTH_SUCCESSFUL
    ↓
check_channel_shell_request()
    → shell_ready.set()
    ↓
_run_shell()
    → send fake banner
    → loop: show prompt → read command → send fake response
    → on exit: publish SSH_SESSION event (commands)
```
