"""
init_db.py — Initialize database, run ABE Setup, create admin user
Run this once before starting the Flask application.
"""
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from werkzeug.security import generate_password_hash
from config import Config
from abe_engine import cpabe_setup, cpabe_keygen, serialize_pk, serialize_msk

import sqlite3
import json

DB_PATH = Config.DB_PATH

def run():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    # Apply schema
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path) as f:
        conn.executescript(f.read())

    # --- ABE System Setup ---
    existing_pk = conn.execute(
        "SELECT value FROM system_settings WHERE key='pk'"
    ).fetchone()

    if existing_pk:
        print("[init_db] System keys already initialized. Skipping Setup().")
        pk  = json.loads(existing_pk["value"])
        msk_row = conn.execute(
            "SELECT value FROM system_settings WHERE key='msk'"
        ).fetchone()
        msk = json.loads(msk_row["value"])
    else:
        print("[init_db] Running ABE Setup()...")
        pk, msk = cpabe_setup()
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES ('pk', ?)",
            (serialize_pk(pk),)
        )
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES ('msk', ?)",
            (serialize_msk(msk),)
        )
        print("[init_db] ✅ ABE System keys generated.")

    # --- Create admin user ---
    existing_admin = conn.execute(
        "SELECT id FROM users WHERE username=?", (Config.ADMIN_USERNAME,)
    ).fetchone()

    if existing_admin:
        print(f"[init_db] Admin user '{Config.ADMIN_USERNAME}' already exists.")
    else:
        pw_hash = generate_password_hash(Config.ADMIN_PASSWORD)
        cur = conn.execute(
            """INSERT INTO users (username, name, department, role, paid_dues, password_hash, is_admin)
               VALUES (?,?,?,?,?,?,?)""",
            (Config.ADMIN_USERNAME, Config.ADMIN_NAME, "IT Department",
             "NetworkAdmin", 1, pw_hash, 1)
        )
        admin_id = cur.lastrowid

        # Generate admin private key with all override attributes
        admin_attrs = [
            "dept:it",
            "role:networkadmin",
            "paid:true"
        ]
        admin_sk = cpabe_keygen(pk, msk, admin_attrs, user_id=admin_id)
        conn.execute(
            "INSERT INTO user_keys (user_id, private_key_json) VALUES (?,?)",
            (admin_id, json.dumps(admin_sk))
        )
        print(f"[init_db] ✅ Admin user created.")
        print(f"          Username : {Config.ADMIN_USERNAME}")
        print(f"          Password : {Config.ADMIN_PASSWORD}")

    conn.commit()
    conn.close()
    print("[init_db] ✅ Database initialized successfully.")
    print(f"          DB path : {DB_PATH}")

if __name__ == "__main__":
    run()
