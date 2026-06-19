package server

const serverSchema = `
CREATE TABLE IF NOT EXISTS server_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    token_hash TEXT,
    token_prefix TEXT,
    token_suffix TEXT,
    user_id TEXT,
    client_version TEXT,
    last_ip TEXT,
    last_seen TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_user_devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS server_ops (
    op_id TEXT PRIMARY KEY,
    server_sequence INTEGER,
    device_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    op_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    idempotency_key TEXT,
    client_sequence INTEGER DEFAULT 0,
    last_seen_server_seq INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    pushed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS server_tombstones (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    op_id TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS server_idempotency_keys (
    idempotency_key TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_email_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL,
    device_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_blobs (
    sha256 TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id TEXT,
    device_id TEXT,
    ip TEXT,
    message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_server_ops_sequence ON server_ops(server_sequence);
CREATE INDEX IF NOT EXISTS idx_server_ops_entity ON server_ops(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_server_ops_idempotency ON server_ops(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_server_devices_api_key ON server_devices(api_key);
CREATE INDEX IF NOT EXISTS idx_server_devices_user ON server_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_server_users_username ON server_users(username);
CREATE INDEX IF NOT EXISTS idx_server_users_email ON server_users(email);
CREATE INDEX IF NOT EXISTS idx_server_audit_log_event ON server_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_server_audit_log_created ON server_audit_log(created_at);
`
