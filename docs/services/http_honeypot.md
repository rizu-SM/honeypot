# http_honeypot.py

## Purpose
Emulates a vulnerable web server to capture automated scanners and attackers
probing for common misconfigurations — exposed .env files, WordPress logins,
admin panels, and phpMyAdmin.

## How HTTP works (simplified)
HTTP is a request/response protocol over TCP:

```
Client → "GET /.env HTTP/1.1"          ← attacker requests the file
         "Host: 192.168.1.1"
         "User-Agent: Mozilla/5.0..."

Server → "HTTP/1.1 200 OK"             ← we respond with fake content
         "Server: Apache/2.4.41"
         "Content-Type: text/plain"
         [fake .env content]
```

Every request has: method (GET/POST), path (/.env), headers, body (POST data).
We capture all of it.

## Key concepts

### @app.before_request
Flask calls this function before EVERY request, regardless of which route.
This is where we capture all traffic in one place:
```python
@app.before_request
def capture_request():
    event_bus.publish({
        "protocol": "HTTP",
        "method":   request.method,    # GET, POST, etc.
        "path":     request.path,      # /.env, /wp-login.php, etc.
        "headers":  dict(request.headers),
        "body":     request.get_data()[:2048],  # POST form data, credentials
    })
```
Even if no route matches, `before_request` still fires — so we never
miss a request.

### @app.after_request
Called after every response before it's sent to the client.
We use it to add fake headers that make the server look real:
```python
response.headers["Server"]       = "Apache/2.4.41 (Ubuntu)"
response.headers["X-Powered-By"] = "PHP/7.4.3"
```
Attackers scanning for Apache or PHP vulnerabilities will see what they
expect and continue interacting.

### catch-all route
```python
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return Response("404 Not Found", status=404)
```
Catches every URL that doesn't match a specific route.
This ensures no request goes unhandled — Flask would return a default
404 anyway, but we control the response to keep it looking like Apache.

### use_reloader=False — important!
Flask's development server has a "reloader" that watches files for changes
and restarts the server. It does this by spawning a subprocess.
When Flask runs inside a thread (not the main thread), the reloader
crashes the whole program. Always set `use_reloader=False` in threads.

### create_http_app() factory function
The Flask app is created inside a function, not at module level.
This makes it easy to test — tests can call `create_http_app()` and get
a fresh app without starting a real server.

## Routes and what they capture

| Route | What attackers expect | What we capture |
|-------|-----------------------|-----------------|
| `/.env` | Real app credentials | IP, user agent, headers |
| `/wp-login.php` GET | WordPress login form | IP, scanner fingerprint |
| `/wp-login.php` POST | Submit WP credentials | username + password in body |
| `/admin` | Admin panel | IP, headers |
| `/phpmyadmin` | Database admin | IP, headers |
| `/<anything>` | Whatever they probe | Full request details |

## What we capture per request
```python
{
    "timestamp":  "2024-01-01T12:00:00Z",
    "protocol":   "HTTP",
    "source_ip":  "45.33.32.156",
    "method":     "POST",
    "path":       "/wp-login.php",
    "user_agent": "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
    "headers":    {"Host": "...", "Content-Type": "..."},
    "body":       "log=admin&pwd=password123&wp-submit=Log+In",
}
```

## Flow
```
Attacker sends HTTP request
    ↓
before_request() fires → publish event to EventBus
    ↓
Matching route handler runs → builds response
    ↓
after_request() fires → adds fake Server/X-Powered-By headers
    ↓
Response sent to attacker
```
