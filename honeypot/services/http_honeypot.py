import datetime
import threading

from flask import Flask, Response, request

from honeypot.core.config import Config
from honeypot.core.event_bus import EventBus
from honeypot.core.logger import get_logger
from honeypot.services.base import BaseService

logger = get_logger(__name__)

# Fake .env file — looks like a real Laravel/Node app misconfiguration
FAKE_ENV = """APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:SomeRandomBase64KeyThatLooksReal=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=SuperSecret_Prod_2024!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE_FAKE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI_FAKE_KEY_FOR_HONEYPOT
AWS_DEFAULT_REGION=us-east-1

MAIL_PASSWORD=smtp_password_here
STRIPE_SECRET=sk_test_FAKE_HONEYPOT_KEY_NOT_REAL
"""

# Fake WordPress login page
FAKE_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; Site &#8212; WordPress</title></head>
<body class="login">
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <form method="post" action="/wp-login.php">
    <p><label>Username<input type="text" name="log" /></label></p>
    <p><label>Password<input type="password" name="pwd" /></label></p>
    <input type="submit" value="Log In" />
  </form>
  <p id="backtoblog"><a href="/">&larr; Go to Site</a></p>
</div>
</body></html>"""

# Fake admin login page
FAKE_ADMIN = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body>
<h2>Administration Login</h2>
<form method="post">
  <input type="text" name="username" placeholder="Username" /><br/>
  <input type="password" name="password" placeholder="Password" /><br/>
  <input type="submit" value="Login" />
</form>
</body></html>"""


def create_http_app(config: Config, event_bus: EventBus) -> Flask:
    """
    Build and return the Flask app for the HTTP honeypot.
    Separated from the service class so it can be tested independently.
    """
    app = Flask(__name__)

    @app.before_request
    def capture_request():
        """Called before every request — captures everything into the EventBus."""
        event_bus.publish({
            "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "protocol":    "HTTP",
            "source_ip":   request.remote_addr,
            "source_port": 0,
            "method":      request.method,
            "path":        request.path,
            "user_agent":  request.user_agent.string,
            "headers":     dict(request.headers),
            # Limit body to 2KB — avoid storing huge uploads
            "body":        request.get_data(as_text=True)[:2048],
        })
        logger.info("HTTP request", extra={"extra": {
            "ip":     request.remote_addr,
            "method": request.method,
            "path":   request.path,
        }})

    @app.after_request
    def add_fake_headers(response: Response) -> Response:
        """Make responses look like they came from a real Apache/PHP server."""
        response.headers["Server"]        = "Apache/2.4.41 (Ubuntu)"
        response.headers["X-Powered-By"]  = "PHP/7.4.3"
        return response

    # ------------------------------------------------------------------
    # Routes — common targets attackers probe
    # ------------------------------------------------------------------

    @app.route("/.env")
    def fake_env():
        """Most commonly scanned file — devs accidentally expose real .env files."""
        return Response(FAKE_ENV, mimetype="text/plain", status=200)

    @app.route("/wp-login.php", methods=["GET", "POST"])
    def wp_login():
        if request.method == "POST":
            # Credentials submitted — already captured by before_request
            # Return a fake "wrong password" error to keep them trying
            return Response(
                FAKE_WP_LOGIN.replace("</form>",
                    '<p style="color:red">ERROR: Invalid username.</p></form>'),
                mimetype="text/html",
            )
        return Response(FAKE_WP_LOGIN, mimetype="text/html")

    @app.route("/admin", methods=["GET", "POST"])
    @app.route("/admin/", methods=["GET", "POST"])
    def admin_panel():
        return Response(FAKE_ADMIN, mimetype="text/html")

    @app.route("/phpmyadmin", methods=["GET", "POST"])
    @app.route("/phpmyadmin/", methods=["GET", "POST"])
    def phpmyadmin():
        return Response(FAKE_ADMIN.replace("Administration Login", "phpMyAdmin"),
                        mimetype="text/html")

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path: str):
        """Catch every other request — return a generic 404."""
        return Response(
            "<html><body><h1>404 Not Found</h1>"
            "<p>The requested URL was not found on this server.</p>"
            "<hr/><address>Apache/2.4.41 (Ubuntu) Server</address>"
            "</body></html>",
            status=404,
            mimetype="text/html",
        )

    return app


class HTTPHoneypot(BaseService):

    def __init__(self, config: Config, event_bus: EventBus):
        super().__init__(config, event_bus)

    def _run(self):
        app = create_http_app(self.config, self.event_bus)
        self.logger.info(f"HTTP honeypot listening on port {self.config.http_port}")

        # use_reloader=False — MUST be False when running inside a thread
        # debug=False        — debug mode tries to run in the main thread only
        app.run(
            host="0.0.0.0",
            port=self.config.http_port,
            threaded=True,
            use_reloader=False,
            debug=False,
        )
