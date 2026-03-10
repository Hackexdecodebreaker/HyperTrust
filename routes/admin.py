"""
routes/admin.py — Admin dashboard, user management, logs, benchmark
"""

import json
from flask import (Blueprint, render_template, request,
                   redirect, url_for, session, flash, jsonify)
from werkzeug.security import generate_password_hash
from functools import wraps

from db import (get_db, get_all_users, get_user_by_id,
                get_user_attributes, get_all_logs,
                save_user_private_key, get_system_pk, get_system_msk)
from abe_engine import cpabe_keygen
from crypto_utils import benchmark_encryption

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Session expired or invalid. Please log in again.", "warning")
            return redirect(url_for("auth.login"))
        if not session.get("is_admin"):
            return render_template("errors/403.html"), 403
        return f(*args, **kwargs)
    return decorated


# ─── Dashboard ───────────────────────────────────────────────────────────────

@admin_bp.route("/")
@admin_required
def dashboard():
    db = get_db()
    users      = get_all_users(db)
    logs       = get_all_logs(db)
    total_ok   = sum(1 for l in logs if l["success"])
    total_deny = sum(1 for l in logs if not l["success"])
    recent     = logs[:10]

    pk = get_system_pk(db)
    active_policy = db.execute(
        "SELECT policy FROM access_tokens ORDER BY created_at DESC LIMIT 1"
    ).fetchone()

    return render_template(
        "admin/dashboard.html",
        users=users,
        recent_logs=recent,
        total_users=len(users),
        total_ok=total_ok,
        total_deny=total_deny,
        active_policy=active_policy["policy"] if active_policy else "—"
    )


# ─── User Management ─────────────────────────────────────────────────────────

DEFAULT_POLICY = (
    "((dept:cse and paid:true) or (role:networkadmin or role:itsupport))"
)

@admin_bp.route("/users")
@admin_required
def users():
    db    = get_db()
    users = get_all_users(db)
    attr_map = {}
    for u in users:
        attr_map[u["id"]] = get_user_attributes(db, u["id"])
    return render_template("admin/users.html", users=users, attr_map=attr_map)


@admin_bp.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    db         = get_db()
    name       = request.form.get("name", "").strip()
    username   = request.form.get("username", "").strip()
    password   = request.form.get("password", "").strip()
    department = request.form.get("department", "").strip()
    role       = request.form.get("role", "Student").strip()
    paid_dues  = 1 if request.form.get("paid_dues") == "true" else 0

    if not all([name, username, password, department]):
        flash("All fields are required.", "danger")
        return redirect(url_for("admin.dashboard"))

    existing = db.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    if existing:
        flash(f"Username '{username}' already exists.", "warning")
        return redirect(url_for("admin.dashboard"))

    pw_hash = generate_password_hash(password)
    cur = db.execute(
        """INSERT INTO users (username, name, department, role, paid_dues, password_hash)
           VALUES (?,?,?,?,?,?)""",
        (username, name, department, role, paid_dues, pw_hash)
    )
    user_id = cur.lastrowid

    # Build attributes list
    dept_key = department.lower().replace(" ", "")
    role_key = role.lower().replace(" ", "")
    paid_key = "true" if paid_dues else "false"
    attributes = [
        f"dept:{dept_key}",
        f"role:{role_key}",
        f"paid:{paid_key}"
    ]

    pk  = get_system_pk(db)
    msk = get_system_msk(db)

    if pk and msk:
        sk = cpabe_keygen(pk, msk, attributes, user_id=user_id)
        save_user_private_key(db, user_id, sk)

    db.commit()
    flash(f"User '{name}' added with attributes: {', '.join(attributes)}", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def delete_user(uid: int):
    db = get_db()
    user = get_user_by_id(db, uid)
    if not user:
        flash("User not found.", "danger")
    elif user["is_admin"]:
        flash("Cannot delete the admin account.", "warning")
    else:
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
        flash(f"User '{user['username']}' deleted.", "success")
    return redirect(url_for("admin.users"))


# ─── Logs ────────────────────────────────────────────────────────────────────

@admin_bp.route("/logs")
@admin_required
def logs():
    db   = get_db()
    logs = get_all_logs(db)
    return render_template("admin/logs.html", logs=logs)


# ─── Policy viewer ───────────────────────────────────────────────────────────

@admin_bp.route("/policy")
@admin_required
def policy():
    db = get_db()
    token_row = db.execute(
        "SELECT * FROM access_tokens ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    return render_template(
        "admin/policy.html",
        active_policy=token_row["policy"] if token_row else DEFAULT_POLICY,
        default_policy=DEFAULT_POLICY
    )


# ─── Performance Benchmark ───────────────────────────────────────────────────

@admin_bp.route("/benchmark")
@admin_required
def benchmark():
    db = get_db()
    pk = get_system_pk(db)
    results = benchmark_encryption(pk, [3, 5, 10])
    return render_template("admin/benchmark.html", results=results)
