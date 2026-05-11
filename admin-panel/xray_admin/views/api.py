"""AJAX endpoints (uuid generate, port check, logs tail, system stats, etc)."""
import uuid as uuid_module

from flask import Blueprint, jsonify, request

from ..auth import login_required
from ..config import ACCESS_LOG, ERROR_LOG
from ..logs import parse_access_line, parse_error_line, tail_file
from ..outbounds import read_outbounds, write_outbounds
from ..routing import read_routing_rules, write_routing_rules
from ..stats import get_system_stats
from ..state import validate_port
from ..system import systemctl


bp = Blueprint("api", __name__)


@bp.route("/api/generate-uuid")
@login_required
def api_generate_uuid():
    return jsonify({"uuid": str(uuid_module.uuid4())})


@bp.route("/api/check-port")
@login_required
def api_check_port():
    port_str = request.args.get("port", "")
    exclude_tag = request.args.get("exclude_tag", "") or None
    try:
        port = validate_port(port_str, exclude_tag=exclude_tag)
        return jsonify({"valid": True, "port": port})
    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)})


@bp.route("/api/system/stats")
@login_required
def api_system_stats():
    return jsonify(get_system_stats())


@bp.route("/api/logs/<kind>")
@login_required
def api_logs(kind: str):
    if kind not in ("access", "error"):
        return jsonify({"error": "unknown log"}), 400
    path = ACCESS_LOG if kind == "access" else ERROR_LOG
    n = int(request.args.get("n", 200))
    n = max(10, min(n, 2000))
    raw = tail_file(path, n=n)
    if kind == "access":
        parsed = [parse_access_line(line) for line in raw]
    else:
        parsed = [parse_error_line(line) for line in raw]
    parsed = [p for p in parsed if p]
    return jsonify({"lines": parsed, "exists": path.exists()})


@bp.route("/api/routing/reorder", methods=["POST"])
@login_required
def api_routing_reorder():
    data = request.get_json(silent=True) or {}
    order = data.get("order")
    if not isinstance(order, list):
        return jsonify({"error": "bad order"}), 400
    rules = read_routing_rules()
    if sorted(order) != list(range(len(rules))):
        return jsonify({"error": "order doesn't cover all rules"}), 400
    new_rules = [rules[i] for i in order]
    write_routing_rules(new_rules)
    systemctl("restart")
    return jsonify({"ok": True})
