package server

import (
	"database/sql"
	"net/http"
	"strings"
	"time"
)

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (deviceID, userID string, ok bool) {
	key := r.Header.Get("Authorization")
	key = strings.TrimPrefix(key, "Bearer ")
	if key == "" {
		key = r.URL.Query().Get("api_key")
	}
	if key == "" {
		jsonErr(w, 401, "API key required")
		return "", "", false
	}
	hash := sha256Hex(key)
	var deviceIDVal, userIDVal, revokedAt sql.NullString
	err := s.db.QueryRow("SELECT id, user_id, revoked_at FROM server_devices WHERE token_hash=?", hash).Scan(&deviceIDVal, &userIDVal, &revokedAt)
	if err == nil {
		if revokedAt.Valid && revokedAt.String != "" {
			jsonErr(w, 401, "device revoked")
			return "", "", false
		}
		if userIDVal.Valid && userIDVal.String != "" {
			var blocked int
			s.db.QueryRow("SELECT blocked FROM server_users WHERE id=?", userIDVal.String).Scan(&blocked)
			if blocked != 0 {
				jsonErr(w, 403, "user blocked")
				return "", "", false
			}
		}
		s.db.Exec("UPDATE server_devices SET last_seen=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), deviceIDVal.String)
		return deviceIDVal.String, userIDVal.String, true
	}
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM server_devices WHERE api_key=?", key).Scan(&count)
	if err != nil || count == 0 {
		jsonErr(w, 401, "invalid API key")
		return "", "", false
	}
	return "", "", true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil || !s.tokens.Check(cookie.Value) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return false
	}
	return true
}

type PasswordError string

const (
	ErrPasswordTooShort PasswordError = "PASSWORD_TOO_SHORT"
	ErrPasswordTooLong  PasswordError = "PASSWORD_TOO_LONG"
)

func validatePassword(password string) string {
	if len(password) < 8 {
		return string(ErrPasswordTooShort)
	}
	if len(password) > 256 {
		return string(ErrPasswordTooLong)
	}
	return ""
}
