"""
routes/auth.py — Authentication (Login / Logout)
"""

from flask import (Blueprint, render_template, request,
                   redirect, url_for, session, flash)
from werkzeug.security import check_password_hash
from db import get_db, get_user_by_username

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        if session.get("is_admin"):
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("user.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("auth.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = get_user_by_username(db, username)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["name"]     = user["name"]
            session["is_admin"] = bool(user["is_admin"])
            if user["is_admin"]:
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("user.dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
