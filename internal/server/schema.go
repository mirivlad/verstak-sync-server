package server

import (
	"database/sql"
	"fmt"
)

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
    legacy_api_key INTEGER NOT NULL DEFAULT 0,
    user_id TEXT,
    vault_id TEXT,
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
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
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
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    op_id TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, vault_id, entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS server_idempotency_keys (
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, vault_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS server_email_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_hash TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS server_blob_refs (
    user_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_accessed TEXT NOT NULL,
    PRIMARY KEY (user_id, vault_id, sha256)
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
CREATE INDEX IF NOT EXISTS idx_server_blob_refs_scope ON server_blob_refs(user_id, vault_id, sha256);
CREATE INDEX IF NOT EXISTS idx_server_blob_refs_user ON server_blob_refs(user_id, sha256);
CREATE INDEX IF NOT EXISTS idx_server_sessions_expiry ON server_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_server_sessions_subject ON server_sessions(scope, subject_id);

CREATE TABLE IF NOT EXISTS server_smtp_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

type sqliteColumn struct {
	primaryKeyOrder int
}

const schemaVersion = 2

func migrateServerSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, change := range []struct {
		table      string
		column     string
		definition string
	}{
		{"server_devices", "user_id", "TEXT"},
		{"server_devices", "vault_id", "TEXT"},
		{"server_ops", "user_id", "TEXT"},
		{"server_ops", "vault_id", "TEXT"},
	} {
		if err := ensureSQLiteColumn(tx, change.table, change.column, change.definition); err != nil {
			return err
		}
	}

	if err := backfillDeviceOwners(tx); err != nil {
		return err
	}
	if err := migrateLegacyDeviceCredentials(tx); err != nil {
		return err
	}
	if err := migrateEmailTokenHashes(tx); err != nil {
		return err
	}
	if err := backfillOperationScope(tx); err != nil {
		return err
	}
	if err := migrateTombstoneScope(tx); err != nil {
		return err
	}
	if err := migrateIdempotencyScope(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_ops_scope_sequence
		ON server_ops(user_id, vault_id, server_sequence)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_devices_scope
		ON server_devices(user_id, vault_id)`); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return err
	}

	return tx.Commit()
}

func migrateLegacyDeviceCredentials(tx *sql.Tx) error {
	if err := ensureSQLiteColumn(tx, "server_devices", "legacy_api_key", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// Existing rows predate the hash-only enrollment path. Their API keys keep
	// working only when explicitly marked legacy; devices enrolled by this
	// version store a disabled placeholder and can never authenticate with it.
	_, err := tx.Exec(`UPDATE server_devices SET legacy_api_key=1
		WHERE legacy_api_key=0 AND api_key NOT LIKE 'disabled:%'`)
	return err
}

func migrateEmailTokenHashes(tx *sql.Tx) error {
	columns, err := sqliteTableColumns(tx, "server_email_tokens")
	if err != nil {
		return err
	}
	if _, ok := columns["token_hash"]; ok {
		return nil
	}
	if _, err := tx.Exec("ALTER TABLE server_email_tokens RENAME TO server_email_tokens_legacy"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE server_email_tokens (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		purpose TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT token, user_id, purpose, expires_at, created_at FROM server_email_tokens_legacy`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var token, userID, purpose, expiresAt, createdAt string
		if err := rows.Scan(&token, &userID, &purpose, &expiresAt, &createdAt); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO server_email_tokens (token_hash, user_id, purpose, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?)`, sha256Hex(token), userID, purpose, expiresAt, createdAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = tx.Exec("DROP TABLE server_email_tokens_legacy")
	return err
}

func ensureSQLiteColumn(tx *sql.Tx, table, column, definition string) error {
	columns, err := sqliteTableColumns(tx, table)
	if err != nil {
		return err
	}
	if _, ok := columns[column]; ok {
		return nil
	}
	if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

func sqliteTableColumns(tx *sql.Tx, table string) (map[string]sqliteColumn, error) {
	rows, err := tx.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := make(map[string]sqliteColumn)
	for rows.Next() {
		var cid, notNull, primaryKeyOrder int
		var name, dataType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKeyOrder); err != nil {
			return nil, err
		}
		columns[name] = sqliteColumn{primaryKeyOrder: primaryKeyOrder}
	}
	return columns, rows.Err()
}

func backfillDeviceOwners(tx *sql.Tx) error {
	_, err := tx.Exec(`UPDATE server_devices
		SET user_id = (
			SELECT user_id FROM server_user_devices
			WHERE device_id = server_devices.id
		)
		WHERE COALESCE(user_id, '') = ''
		  AND 1 = (
			SELECT COUNT(*) FROM server_user_devices
			WHERE device_id = server_devices.id
		)`)
	return err
}

func backfillOperationScope(tx *sql.Tx) error {
	if _, err := tx.Exec(`UPDATE server_ops
		SET user_id = (
			SELECT user_id FROM server_devices
			WHERE id = server_ops.device_id
		)
		WHERE COALESCE(user_id, '') = ''`); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE server_ops
		SET vault_id = COALESCE(
			NULLIF((SELECT vault_id FROM server_devices WHERE id = server_ops.device_id), ''),
			'legacy:' || user_id
		)
		WHERE COALESCE(vault_id, '') = ''
		  AND COALESCE(user_id, '') != ''`)
	return err
}

func migrateTombstoneScope(tx *sql.Tx) error {
	if hasScopedPrimaryKey(tx, "server_tombstones", "user_id", "vault_id", "entity_type", "entity_id") {
		return nil
	}
	if _, err := tx.Exec("ALTER TABLE server_tombstones RENAME TO server_tombstones_legacy"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE server_tombstones (
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		entity_type TEXT NOT NULL,
		entity_id TEXT NOT NULL,
		op_id TEXT NOT NULL,
		deleted_at TEXT NOT NULL,
		PRIMARY KEY (user_id, vault_id, entity_type, entity_id)
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO server_tombstones
		(user_id, vault_id, entity_type, entity_id, op_id, deleted_at)
		SELECT o.user_id, o.vault_id, legacy.entity_type, legacy.entity_id, legacy.op_id, legacy.deleted_at
		FROM server_tombstones_legacy AS legacy
		JOIN server_ops AS o ON o.op_id = legacy.op_id
		WHERE COALESCE(o.user_id, '') != '' AND COALESCE(o.vault_id, '') != ''`); err != nil {
		return err
	}
	_, err := tx.Exec("DROP TABLE server_tombstones_legacy")
	return err
}

func migrateIdempotencyScope(tx *sql.Tx) error {
	if hasScopedPrimaryKey(tx, "server_idempotency_keys", "user_id", "vault_id", "idempotency_key") {
		return nil
	}
	if _, err := tx.Exec("ALTER TABLE server_idempotency_keys RENAME TO server_idempotency_keys_legacy"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE server_idempotency_keys (
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		idempotency_key TEXT NOT NULL,
		response_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (user_id, vault_id, idempotency_key)
	)`); err != nil {
		return err
	}
	// The previous cache was global. Discard it rather than risk replaying a
	// response for another user or vault after the migration.
	_, err := tx.Exec("DROP TABLE server_idempotency_keys_legacy")
	return err
}

func hasScopedPrimaryKey(tx *sql.Tx, table string, want ...string) bool {
	columns, err := sqliteTableColumns(tx, table)
	if err != nil {
		return false
	}
	for index, name := range want {
		column, ok := columns[name]
		if !ok || column.primaryKeyOrder != index+1 {
			return false
		}
	}
	return true
}

func effectiveVaultScope(userID, vaultID string) string {
	if vaultID != "" {
		return vaultID
	}
	if userID == "" {
		return ""
	}
	return "legacy:" + userID
}
