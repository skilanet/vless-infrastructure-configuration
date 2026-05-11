"""xray-admin: Flask application factory."""
from __future__ import annotations

import socket
import time
from pathlib import Path

from flask import Flask, session

from .activity import read_activity  # noqa: F401  (used by views)
from .alerts import load_alerts_state
from .config import get_panel_config
from .format import fmt_bytes, fmt_humans_ago, fmt_short_uuid
from .metrics import ensure_sampler
from .state import collect_users
from .vless import get_server_ip
from .views import register_blueprints


def create_app() -> Flask:
    panel_config = get_panel_config()

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent.parent / "templates"),
        static_folder=str(Path(__file__).parent.parent / "static"),
    )
    app.secret_key = panel_config["secret_key"]

    register_blueprints(app)

    static_css = Path(app.static_folder) / "style.css"

    def _asset_version() -> str:
        try:
            return str(int(static_css.stat().st_mtime))
        except OSError:
            return "0"

    @app.before_request
    def _bootstrap_metrics():
        ensure_sampler()

    @app.context_processor
    def inject_globals():
        try:
            if session.get("logged_in"):
                active = [a for a in load_alerts_state().get("active", [])
                          if isinstance(a, dict)]
            else:
                active = []
        except Exception:
            active = []
        try:
            users_count = len(collect_users()) if session.get("logged_in") else 0
        except Exception:
            users_count = 0
        hostname = panel_config.get("hostname") or socket.gethostname() or "xray"
        return {
            "nav_active_alerts": len(active),
            "nav_users_count": users_count,
            "server_ip": get_server_ip(),
            "server_hostname": hostname,
            "asset_version": _asset_version(),
            "fmt_bytes": fmt_bytes,
            "fmt_short_uuid": fmt_short_uuid,
            "fmt_humans_ago": fmt_humans_ago,
        }

    return app
