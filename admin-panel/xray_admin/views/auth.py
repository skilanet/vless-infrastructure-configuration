"""Login / logout."""
import hmac
import time

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from ..config import get_panel_config

bp = Blueprint("auth", __name__)

# ponytail: per-worker in-memory login lockout (gunicorn runs 2 workers → the
# effective limit is ~2× these numbers). Good enough behind 127.0.0.1/SSH-tunnel;
# move to a shared store or fail2ban if the panel ever faces the open internet.
_FAILS: dict[str, list[float]] = {}
_MAX_FAILS = 10
_WINDOW = 900  # 15 минут


def _locked_out(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _FAILS.get(ip, []) if now - t < _WINDOW]
    if recent:
        _FAILS[ip] = recent
    else:
        _FAILS.pop(ip, None)
    return len(recent) >= _MAX_FAILS


def _safe_next(nxt: str) -> str:
    # только локальные пути: блокируем //evil.com и абсолютные URL
    if not nxt.startswith("/") or nxt.startswith("//"):
        return "/"
    return nxt


@bp.route("/login", methods=["GET", "POST"])
def login():
    cfg = get_panel_config()
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if _locked_out(ip):
            flash("слишком много попыток, подожди 15 минут", "error")
            return render_template("login.html"), 429
        login_input = request.form.get("login", "")
        password = request.form.get("password", "")
        login_ok = hmac.compare_digest(login_input, cfg["admin_login"])
        if (login_ok and
                check_password_hash(cfg["admin_password_hash"], password)):
            _FAILS.pop(ip, None)
            session["logged_in"] = True
            session["login"] = login_input
            session.permanent = True
            return redirect(_safe_next(request.args.get("next", "/")))
        _FAILS.setdefault(ip, []).append(time.time())
        flash("неверный логин или пароль", "error")
    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
