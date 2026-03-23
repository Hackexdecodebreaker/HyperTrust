"""
routes/user.py — User dashboard, WiFi access request, personal logs
"""

import json
from flask import (Blueprint, render_template, request,
                   redirect, url_for, session, flash)
from functools import wraps

from db import (get_db, get_user_by_id, get_user_private_key, save_user_private_key,
                get_user_attributes, get_user_logs,
                save_access_token, log_access,
                get_system_pk, get_system_msk, save_payment, update_payment_status,
                get_user_payments, update_user_paid_status, get_user_attributes_base,
                get_all_resource_policies, get_resource_policy, get_latest_token,
                get_wifi_policy)
from abe_engine import cpabe_keygen
from crypto_utils import generate_wifi_token, encrypt_token, decrypt_token

user_bp = Blueprint("user", __name__, url_prefix="/user")


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
    
    # Get current WiFi policy from system_settings
    current_policy = get_wifi_policy(db)

    return render_template(
        "user/dashboard.html",
        user=user,
        attributes=attributes,
        recent_logs=recent_logs,
        policy=current_policy
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

    # Use current active WiFi policy from system_settings
    policy = get_wifi_policy(db)

    # Generate and hybrid-encrypt a new WiFi token
    token_str = generate_wifi_token()
    bundle    = encrypt_token(token_str, policy, pk)

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
        flash(f"Access Granted — Token: {result}", "success")
    else:
        log_access(db, user_id, token_id, success=False,
                   reason="Attributes did not satisfy policy")
        db.commit()
        flash("Access Denied — Your attributes do not satisfy the access policy.", "danger")

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
    # Allowed portals - now including department portals
    allowed_portals = [
        "research_data", "confidential_docs",
        "computer_science", "information_technology", "electrical_engineering",
        "mechanical_engineering", "civil_engineering", "business_administration"
    ]
    
    if portal_name not in allowed_portals:
        flash("Portal not found.", "danger")
        return redirect(url_for("user.dashboard"))
        
    db         = get_db()
    user_id    = session["user_id"]
    pk         = get_system_pk(db)
    private_key = get_user_private_key(db, user_id)

    if not pk or not private_key:
        flash("Your cryptographic key has not been set up yet. Contact admin.", "danger")
        return redirect(url_for("user.dashboard"))

    # Check if user is admin - admins can access everything
    if session.get("is_admin"):
        # Get resource policy from database for display purposes
        resource_policy = get_resource_policy(db, portal_name)
        policy = f"paid:true and ({resource_policy['policy']})" if resource_policy else "Admin Override"
        
        portal_titles = {
            "research_data": "Research Data Portal",
            "confidential_docs": "Confidential Documents",
            "computer_science": "Computer Science Department Portal",
            "information_technology": "Information Technology Department Portal",
            "electrical_engineering": "Electrical Engineering Department Portal",
            "mechanical_engineering": "Mechanical Engineering Department Portal",
            "civil_engineering": "Civil Engineering Department Portal",
            "business_administration": "Business Administration Department Portal"
        }
        
        return render_template(f"user/portal_{portal_name}.html", 
                             portal_title=portal_titles.get(portal_name, portal_name.title()),
                             policy=policy)
    
    # Get resource policy from database
    resource_policy = get_resource_policy(db, portal_name)
    
    if not resource_policy:
        flash("Resource policy not configured.", "danger")
        return redirect(url_for("user.resources"))
    
    # Policy structure: payment is ALWAYS required, ANDed with admin-set additional attributes
    policy = f"paid:true and ({resource_policy['policy']})"
    
    # Test access using ABE
    bundle = encrypt_token("PORTAL_ACCESS", policy, pk)
    result = decrypt_token(bundle, private_key, pk)

    if result:
        # User satisfies the policy! Let them in.
        portal_titles = {
            "research_data": "Research Data Portal",
            "confidential_docs": "Confidential Documents",
            "computer_science": "Computer Science Department Portal",
            "information_technology": "Information Technology Department Portal",
            "electrical_engineering": "Electrical Engineering Department Portal",
            "mechanical_engineering": "Mechanical Engineering Department Portal",
            "civil_engineering": "Civil Engineering Department Portal",
            "business_administration": "Business Administration Department Portal"
        }
        
        return render_template(f"user/portal_{portal_name}.html", 
                             portal_title=portal_titles.get(portal_name, portal_name.title()),
                             policy=policy)
    else:
        # Access denied. Policy not satisfied.
        flash(f"Access Denied — Your ABE attributes do not satisfy the policy required for {portal_name.replace('_', ' ').title()}.", "danger")
        return redirect(url_for("user.resources"))


@user_bp.route("/resources")
@login_required
def resources():
    db = get_db()
    user = get_user_by_id(db, session["user_id"])
    attributes = get_user_attributes(db, session["user_id"])
    
    # Get all active resource policies from database
    resource_policies = get_all_resource_policies(db)
    
    # Build resources list from database policies
    resources = []
    for rp in resource_policies:
        resources.append({
            "id": rp["resource_id"],
            "name": rp["name"],
            "description": rp["description"],
            "icon": rp["icon"],
            "policy": f"paid:true and ({rp['policy']})",  # Payment always required
            "category": rp["category"]
        })
    
    # Check if user is admin - admins can access everything
    if session.get("is_admin"):
        for resource in resources:
            resource["has_access"] = True
    else:
        # Check access for each resource using ABE
        pk = get_system_pk(db)
        private_key = get_user_private_key(db, session["user_id"])
        
        for resource in resources:
            if pk and private_key:
                # Test access using ABE with the combined policy (paid:true AND admin policy)
                bundle = encrypt_token("RESOURCE_ACCESS", resource["policy"], pk)
                result = decrypt_token(bundle, private_key, pk)
                resource["has_access"] = bool(result)
            else:
                resource["has_access"] = False
    
    return render_template("user/resources.html", user=user, resources=resources, attributes=attributes)


@user_bp.route("/payment")
@login_required
def payment():
    db = get_db()
    user = get_user_by_id(db, session["user_id"])
    payments = get_user_payments(db, session["user_id"])
    return render_template("user/payment.html", user=user, payments=payments)


@user_bp.route("/payment/process", methods=["POST"])
@login_required
def process_payment():
    amount = request.form.get("amount", "").strip()
    payment_method = request.form.get("payment_method", "simulated")

    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError):
        flash("Invalid payment amount.", "danger")
        return redirect(url_for("user.payment"))

    db = get_db()
    user_id = session["user_id"]

    # Create payment record
    payment_id = save_payment(
        db,
        user_id=user_id,
        amount=amount,
        currency="USD",
        payment_method=payment_method,
        description=f"Network access fee payment - ${amount}"
    )

    # Simulate payment processing
    import time
    import random

    # Simulate processing delay
    time.sleep(1)

    # Simulate payment success/failure (90% success rate)
    success = random.random() < 0.9
    transaction_id = f"sim_txn_{payment_id}_{int(time.time())}"

    if success:
        update_payment_status(db, payment_id, "completed", transaction_id)
        # Update user's paid status
        update_user_paid_status(db, user_id, True)
        
        # Regenerate ABE private key with updated paid:true attribute
        user = get_user_by_id(db, user_id)
        attributes = get_user_attributes_base(user)
        pk = get_system_pk(db)
        msk = get_system_msk(db)
        
        if pk and msk:
            sk = cpabe_keygen(pk, msk, attributes, user_id=user_id)
            save_user_private_key(db, user_id, sk)
            flash(f"Payment of ${amount:.2f} processed successfully! Account marked as paid and ABE key updated with 'paid:true' attribute.", "success")
        else:
            flash(f"Payment of ${amount:.2f} processed successfully! Account marked as paid (keys unavailable). Contact admin for ABE update.", "warning")
        
        db.commit()
    else:
        update_payment_status(db, payment_id, "failed", transaction_id)
        db.commit()
        flash("Payment failed. Please try again or contact support.", "danger")

    return redirect(url_for("user.payment"))

