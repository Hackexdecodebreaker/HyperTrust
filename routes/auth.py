"""
routes/auth.py — Authentication (Login / Logout)
"""

from flask import (Blueprint, render_template, request,
                   redirect, url_for, session, flash)
from werkzeug.security import check_password_hash, generate_password_hash
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


@auth_bp.route("/register", methods=["POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("auth.index"))

    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    department = request.form.get("department", "").strip()
    role = request.form.get("role", "Student").strip()

    if not all([name, username, password, department]):
        flash("All fields are required.", "danger")
        return redirect(url_for("auth.login"))

    db = get_db()

    # Check if username already exists
    existing = get_user_by_username(db, username)
    if existing:
        flash(f"Username '{username}' already exists. Please choose a different one.", "warning")
        return redirect(url_for("auth.login"))

    # Create new user
    pw_hash = generate_password_hash(password)
    cur = db.execute(
        """INSERT INTO users (username, name, department, role, paid_dues, password_hash, is_admin)
           VALUES (?,?,?,?,?,?,?)""",
        (username, name, department, role, 0, pw_hash, 0)  # paid_dues defaults to 0 (false)
    )
    user_id = cur.lastrowid

    # Generate ABE keys for the new user
    from db import save_user_private_key, get_system_pk, get_system_msk
    from abe_engine import cpabe_keygen

    pk = get_system_pk(db)
    msk = get_system_msk(db)

    if pk and msk:
        # Build attributes based on user input
        dept_key = department.lower().replace(" ", "")
        role_key = role.lower().replace(" ", "")
        attributes = [
            f"dept:{dept_key}",
            f"role:{role_key}",
            "paid:false"  # New users haven't paid yet
        ]

        sk = cpabe_keygen(pk, msk, attributes, user_id=user_id)
        save_user_private_key(db, user_id, sk)

    db.commit()
    flash(f"Account created successfully! You can now log in with username '{username}'.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
