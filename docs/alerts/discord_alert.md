# discord_alert.py

## Purpose
Sends attack notifications to a Discord channel when the attack count
hits a configurable threshold. Lets you monitor the honeypot from your
phone without watching the terminal.

## How Discord webhooks work
Discord gives you a special URL (webhook). You send a POST request with
JSON to that URL and Discord posts it as a message in your channel.
No special library needed — just a plain HTTP POST.

```
POST https://discord.com/api/webhooks/ID/TOKEN
Content-Type: application/json

{"embeds": [{"title": "Attack from 1.2.3.4", "color": 0x3498DB, ...}]}
```

Discord responds with HTTP 204 (No Content) on success.

## Key concepts

### Threshold counter
We don't alert on every attack — that would be spam.
We count attacks and alert every N (default 10):
```
attack 1  → counter = 1  → no alert
attack 5  → counter = 5  → no alert
attack 10 → counter = 10 → SEND ALERT → reset counter to 0
attack 11 → counter = 1  → no alert (fresh cycle)
```

### threading.Lock on counter
The counter is shared between all EventBus calls.
Multiple events can arrive at nearly the same time, so we protect
the counter with a Lock to prevent race conditions:
```python
with self._lock:
    self._counter += 1          # only one thread can be here at once
    if self._counter >= self.threshold:
        self._send_alert(event)
        self._counter = 0
```
Without the lock, two threads could both read counter=9, both increment
to 10, and both send an alert at the same time.

### No-op when webhook not configured
```python
if not self.webhook_url:
    return
```
If DISCORD_WEBHOOK_URL is empty in .env, the method returns immediately.
No errors, no crashes — the feature is simply disabled.

### Discord embed format
An embed is a rich message card with a colored border, title, and fields:
```
┌─[blue]──────────────────────────────┐
│ [SSH] Attack from 45.33.32.156       │
│ 10 attacks reached — showing latest  │
│                                      │
│ Username: root   Password: toor      │
│ Country: United States               │
│                          HoneyTrap   │
└──────────────────────────────────────┘
```
Each protocol gets its own color:
SSH=blue, FTP=orange, Telnet=red, HTTP=green

## How to set up a Discord webhook
1. Open Discord → your server → channel settings
2. Integrations → Webhooks → New Webhook
3. Copy the webhook URL
4. Paste it in your .env file:
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
   DISCORD_ALERT_THRESHOLD=10

## Flow
```
EventBus delivers event → discord.handle(event)
    ↓
webhook configured? No  → return immediately
webhook configured? Yes → increment counter
    ↓
counter < threshold → do nothing
counter = threshold → _send_alert(event) → requests.post(webhook_url)
                    → reset counter to 0
```
