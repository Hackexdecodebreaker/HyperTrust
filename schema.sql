-- schema.sql — HyperTrust Database Schema

-- System-wide ABE keys (pk, msk stored server-side)
CREATE TABLE IF NOT EXISTS system_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    name         TEXT    NOT NULL,
    department   TEXT    NOT NULL DEFAULT '',
    role         TEXT    NOT NULL DEFAULT 'Student',
    paid_dues    INTEGER NOT NULL DEFAULT 0,   -- 1=True, 0=False
    password_hash TEXT   NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User private keys (serialized ABE key)
CREATE TABLE IF NOT EXISTS user_keys (
    user_id          INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    private_key_json TEXT    NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Encrypted access tokens
CREATE TABLE IF NOT EXISTS access_tokens (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_token  TEXT    NOT NULL,   -- AES-GCM ciphertext (hex)
    nonce            TEXT    NOT NULL,   -- AES-GCM nonce (hex)
    tag              TEXT    NOT NULL,   -- AES-GCM auth tag (hex)
    encrypted_aes_key TEXT   NOT NULL,  -- ABE ciphertext (JSON)
    policy           TEXT    NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Access attempt logs
CREATE TABLE IF NOT EXISTS access_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    token_id     INTEGER REFERENCES access_tokens(id),
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    success      INTEGER NOT NULL DEFAULT 0,
    reason       TEXT    NOT NULL DEFAULT ''
);

-- Payment records
CREATE TABLE IF NOT EXISTS payments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    amount       REAL    NOT NULL,
    currency     TEXT    NOT NULL DEFAULT 'USD',
    status       TEXT    NOT NULL DEFAULT 'pending', -- pending, completed, failed
    payment_method TEXT NOT NULL DEFAULT 'simulated',
    transaction_id TEXT UNIQUE,
    description  TEXT    NOT NULL DEFAULT '',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Resource policies for ABE access control
CREATE TABLE IF NOT EXISTS resource_policies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id  TEXT    NOT NULL UNIQUE,  -- e.g., 'research_data', 'computer_science'
    name         TEXT    NOT NULL,         -- Display name
    description  TEXT    NOT NULL,
    category     TEXT    NOT NULL DEFAULT 'General',
    icon         TEXT    NOT NULL DEFAULT '📄',
    policy       TEXT    NOT NULL,         -- ABE policy string (will be ANDed with paid:true)
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
