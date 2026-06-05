from flask import Flask, render_template

from honeypot.dashboard.api import api_bp


def create_dashboard_app(config, db) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="../../static",
    )
    app.config["SECRET_KEY"] = config.dashboard_secret_key
    app.config["DATABASE"]   = db

    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/map")
    def attack_map():
        return render_template("map.html")

    @app.route("/events")
    def events():
        return render_template("events.html")

    return app
