"""@login_required для всех authenticated routes."""
from functools import wraps

from flask import jsonify, redirect, request, session, url_for


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth required"}), 401
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return wrapper
