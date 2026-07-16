package server

import (
	"database/sql"
	"time"
)

type sqlExecutor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func issueEmailToken(exec sqlExecutor, userID, purpose string, lifetime time.Duration) (string, error) {
	token, err := randomSecret(24)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	_, err = exec.Exec(`INSERT INTO server_email_tokens (token_hash, user_id, purpose, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`, sha256Hex(token), userID, purpose, now.Add(lifetime).Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return token, nil
}

func emailTokenHash(token string) string { return sha256Hex(token) }
