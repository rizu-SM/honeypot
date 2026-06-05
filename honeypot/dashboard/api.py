from flask import Blueprint, jsonify, request, current_app

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/stats")
def stats():
    """Summary numbers — total attacks, unique IPs, top protocols, etc."""
    db = current_app.config["DATABASE"]
    return jsonify(db.get_stats())


@api_bp.route("/events")
def events():
    """Paginated event list with optional filters."""
    db       = current_app.config["DATABASE"]
    page     = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    protocol = request.args.get("protocol")
    country  = request.args.get("country")
    return jsonify(db.get_events(page=page, per_page=per_page,
                                 protocol=protocol, country=country))


@api_bp.route("/attacks/map")
def attack_map():
    """Geo points for the attack map — lat/lon + count per location."""
    db = current_app.config["DATABASE"]
    return jsonify({"markers": db.get_map_data()})


@api_bp.route("/live")
def live():
    """Last 20 events — polled every 5 seconds by the dashboard."""
    db = current_app.config["DATABASE"]
    return jsonify(db.get_events(page=1, per_page=20)["events"])
