"""
routes/user.py — User dashboard, WiFi access request, personal logs
"""

import json
from flask import (Blueprint, render_template, request,
                   redirect, url_for, session, flash)
from functools import wraps

from db import (get_db, get_user_by_id, get_user_private_key,
                get_user_attributes, get_user_logs,
                save_access_token, get_latest_token, log_access,
                get_system_pk)
from crypto_utils import generate_wifi_token, encrypt_token, decrypt_token

user_bp = Blueprint("user", __name__, url_prefix="/user")

# Default policy for WiFi access
WIFI_POLICY = (
    "((dept:cse and paid:true) or (role:networkadmin or role:itsupport))"
)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@user_bp.route("/dashboard")
@login_required
def dashboard():
    db          = get_db()
    user        = get_user_by_id(db, session["user_id"])
    attributes  = get_user_attributes(db, session["user_id"])
    recent_logs = get_user_logs(db, session["user_id"])[:5]

    return render_template(
        "user/dashboard.html",
        user=user,
        attributes=attributes,
        recent_logs=recent_logs,
        policy=WIFI_POLICY
    )


@user_bp.route("/request-access", methods=["POST"])
@login_required
def request_access():
    db         = get_db()
    user_id    = session["user_id"]
    pk         = get_system_pk(db)
    private_key = get_user_private_key(db, user_id)

    if not pk or not private_key:
        flash("Your cryptographic key has not been set up yet. Contact admin.", "danger")
        return redirect(url_for("user.dashboard"))

    # Generate and hybrid-encrypt a new WiFi token
    token_str = generate_wifi_token()
    bundle    = encrypt_token(token_str, WIFI_POLICY, pk)

    if not bundle:
        flash("System error during token encryption.", "danger")
        return redirect(url_for("user.dashboard"))

    # Persist the encrypted token
    token_id = save_access_token(
        db,
        encrypted_token   = bundle["encrypted_token"],
        nonce             = bundle["nonce"],
        tag               = bundle["tag"],
        encrypted_aes_key = bundle["encrypted_aes_key"],
        policy            = bundle["policy"]
    )

    # Attempt decryption with user's private key
    result = decrypt_token(bundle, private_key, pk)

    if result:
        log_access(db, user_id, token_id, success=True,
                   reason="Attributes satisfied policy")
        db.commit()
        flash(f"✅ Access Granted — Token: {result}", "success")
    else:
        log_access(db, user_id, token_id, success=False,
                   reason="Attributes did not satisfy policy")
        db.commit()
        flash("❌ Access Denied — Your attributes do not satisfy the access policy.", "danger")

    return redirect(url_for("user.dashboard"))


@user_bp.route("/logs")
@login_required
def logs():
    db   = get_db()
    logs = get_user_logs(db, session["user_id"])
    return render_template("user/logs.html", logs=logs)


@user_bp.route("/portal/<portal_name>")
@login_required
def secure_portal(portal_name):
    # Allowed portals
    if portal_name not in ["research_data", "confidential_docs"]:
        flash("Portal not found.", "danger")
        return redirect(url_for("user.dashboard"))
        
    db         = get_db()
    user_id    = session["user_id"]
    pk         = get_system_pk(db)
    private_key = get_user_private_key(db, user_id)

    if not pk or not private_key:
        flash("Your cryptographic key has not been set up yet. Contact admin.", "danger")
        return redirect(url_for("user.dashboard"))

    # Test access using the same ABE simulation policy engine.
    # We encrypt a dummy token and see if the user can decrypt it.
    bundle = encrypt_token("PORTAL_ACCESS", WIFI_POLICY, pk)
    result = decrypt_token(bundle, private_key, pk)

    if result:
        # User satisfies the policy! Let them in.
        return render_template(f"user/portal_{portal_name}.html")
    else:
        # Access denied. Policy not satisfied.
        flash(f"❌ Access Denied — Your ABE attributes do not satisfy the policy required for {portal_name.replace('_', ' ').title()}.", "danger")
        return redirect(url_for("user.dashboard"))
