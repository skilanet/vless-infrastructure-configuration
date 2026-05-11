"""Login / logout."""
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from ..config import get_panel_config

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    cfg = get_panel_config()
    if request.method == "POST":
        login_input = request.form.get("login", "")
        password = request.form.get("password", "")
        if (login_input == cfg["admin_login"] and
                check_password_hash(cfg["admin_password_hash"], password)):
            session["logged_in"] = True
            session["login"] = login_input
            session.permanent = True
            return redirect(request.args.get("next", "/"))
        flash("неверный логин или пароль", "error")
    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
