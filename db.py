"""
db.py — SQLite database connection and helpers
"""

import sqlite3
import json
import os
from flask import g, current_app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DB_PATH"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    db_dir = os.path.dirname(app.config["DB_PATH"])
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            pass
            
    with app.app_context():
        db = get_db()
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path) as f:
            db.executescript(f.read())
        db.commit()


# --------------- User helpers -----------------------------------------------

def get_user_by_id(db, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(db, username: str):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_all_users(db):
    return db.execute("SELECT * FROM users ORDER BY id").fetchall()


def get_user_private_key(db, user_id: int) -> dict | None:
    row = db.execute(
        "SELECT private_key_json FROM user_keys WHERE user_id = ?", (user_id,)
    ).fetchone()
    if row:
        return json.loads(row["private_key_json"])
    return None


def save_user_private_key(db, user_id: int, private_key: dict):
    db.execute(
        "INSERT OR REPLACE INTO user_keys (user_id, private_key_json) VALUES (?, ?)",
        (user_id, json.dumps(private_key))
    )


def get_user_attributes(db, user_id: int) -> list[str]:
    row = get_user_private_key(db, user_id)
    if row:
        return row.get("attributes", [])
    return []


# --------------- System key helpers -----------------------------------------

def get_system_pk(db) -> dict | None:
    import json
    row = db.execute("SELECT value FROM system_settings WHERE key = 'pk'").fetchone()
    if row:
        return json.loads(row["value"])
    return None


def get_system_msk(db) -> dict | None:
    import json
    row = db.execute("SELECT value FROM system_settings WHERE key = 'msk'").fetchone()
    if row:
        return json.loads(row["value"])
    return None


def save_system_keys(db, pk: dict, msk: dict):
    import json
    db.execute(
        "INSERT OR REPLACE INTO system_settings (key, value) VALUES ('pk', ?)",
        (json.dumps(pk),)
    )
    db.execute(
        "INSERT OR REPLACE INTO system_settings (key, value) VALUES ('msk', ?)",
        (json.dumps(msk),)  # stored server-side only – never sent to client
    )


# --------------- Access token helpers ---------------------------------------

def save_access_token(db, encrypted_token: str, nonce: str, tag: str,
                      encrypted_aes_key: str, policy: str) -> int:
    cur = db.execute(
        """INSERT INTO access_tokens
           (encrypted_token, nonce, tag, encrypted_aes_key, policy)
           VALUES (?,?,?,?,?)""",
        (encrypted_token, nonce, tag, encrypted_aes_key, policy)
    )
    return cur.lastrowid


def get_latest_token(db) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM access_tokens ORDER BY created_at DESC LIMIT 1"
    ).fetchone()


# --------------- Log helpers ------------------------------------------------

def log_access(db, user_id: int, token_id: int, success: bool, reason: str = ""):
    db.execute(
        """INSERT INTO access_logs (user_id, token_id, success, reason)
           VALUES (?,?,?,?)""",
        (user_id, token_id, 1 if success else 0, reason)
    )


def get_all_logs(db):
    return db.execute(
        """SELECT l.*, u.username, u.name, u.department, u.role
           FROM access_logs l
           JOIN users u ON l.user_id = u.id
           ORDER BY l.attempt_time DESC
           LIMIT 200"""
    ).fetchall()


def get_user_logs(db, user_id: int):
    return db.execute(
        """SELECT l.*, u.username
           FROM access_logs l
           JOIN users u ON l.user_id = u.id
           WHERE l.user_id = ?
           ORDER BY l.attempt_time DESC
           LIMIT 100""",
        (user_id,)
    ).fetchall()
