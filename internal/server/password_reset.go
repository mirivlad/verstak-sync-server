package server

import (
	"database/sql"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	errResetTokenInvalid = errors.New("invalid reset token")
	errResetTokenExpired = errors.New("expired reset token")
)

func (s *Server) resetPasswordWithToken(token, newPassword string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var userID, expiresAt string
	err = tx.QueryRow(`SELECT user_id, expires_at FROM server_email_tokens
		WHERE token_hash=? AND purpose='reset'`, emailTokenHash(token)).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errResetTokenInvalid
	}
	if err != nil {
		return "", err
	}
	expiresAtTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !time.Now().Before(expiresAtTime) {
		return "", errResetTokenExpired
	}

	deleted, err := tx.Exec(`DELETE FROM server_email_tokens
		WHERE token_hash=? AND purpose='reset' AND expires_at=?`, emailTokenHash(token), expiresAt)
	if err != nil {
		return "", err
	}
	deletedCount, err := deleted.RowsAffected()
	if err != nil {
		return "", err
	}
	if deletedCount != 1 {
		return "", errResetTokenInvalid
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	updated, err := tx.Exec("UPDATE server_users SET password_hash=? WHERE id=?", string(hash), userID)
	if err != nil {
		return "", err
	}
	updatedCount, err := updated.RowsAffected()
	if err != nil {
		return "", err
	}
	if updatedCount != 1 {
		return "", errResetTokenInvalid
	}
	if _, err := tx.Exec("DELETE FROM server_email_tokens WHERE user_id=? AND purpose='reset'", userID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return userID, nil
}
