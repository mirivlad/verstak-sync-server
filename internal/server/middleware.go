package server

import (
	"database/sql"
	"net/http"
	"strings"
	"time"
)

type authenticatedDevice struct {
	DeviceID string
	UserID   string
	VaultID  string
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (deviceID, userID string, ok bool) {
	device, ok := s.authenticateDevice(w, r)
	if !ok {
		return "", "", false
	}
	return device.DeviceID, device.UserID, true
}

func (s *Server) requireSyncScope(w http.ResponseWriter, r *http.Request) (authenticatedDevice, bool) {
	device, ok := s.authenticateDevice(w, r)
	if !ok {
		return authenticatedDevice{}, false
	}
	if device.UserID == "" {
		jsonErr(w, http.StatusForbidden, "device is not associated with a user")
		return authenticatedDevice{}, false
	}
	device.VaultID = effectiveVaultScope(device.UserID, device.VaultID)
	if device.VaultID == "" {
		jsonErr(w, http.StatusForbidden, "device is not associated with a vault")
		return authenticatedDevice{}, false
	}
	return device, true
}

func (s *Server) authenticateDevice(w http.ResponseWriter, r *http.Request) (authenticatedDevice, bool) {
	key := r.Header.Get("Authorization")
	key = strings.TrimPrefix(key, "Bearer ")
	if key == "" {
		key = r.URL.Query().Get("api_key")
	}
	if key == "" {
		jsonErr(w, 401, "API key required")
		return authenticatedDevice{}, false
	}

	var device authenticatedDevice
	var userID, vaultID, revokedAt sql.NullString
	err := s.db.QueryRow(`SELECT id, user_id, vault_id, revoked_at
		FROM server_devices WHERE token_hash=?`, sha256Hex(key)).
		Scan(&device.DeviceID, &userID, &vaultID, &revokedAt)
	if err != nil {
		err = s.db.QueryRow(`SELECT id, user_id, vault_id, revoked_at
			FROM server_devices WHERE api_key=?`, key).
			Scan(&device.DeviceID, &userID, &vaultID, &revokedAt)
	}
	if err != nil {
		jsonErr(w, 401, "invalid API key")
		return authenticatedDevice{}, false
	}
	if revokedAt.Valid && revokedAt.String != "" {
		jsonErr(w, 401, "device revoked")
		return authenticatedDevice{}, false
	}
	if userID.Valid {
		device.UserID = userID.String
	}
	if vaultID.Valid {
		device.VaultID = vaultID.String
	}
	if device.UserID != "" {
		var blocked int
		s.db.QueryRow("SELECT blocked FROM server_users WHERE id=?", device.UserID).Scan(&blocked)
		if blocked != 0 {
			jsonErr(w, 403, "user blocked")
			return authenticatedDevice{}, false
		}
	}
	s.db.Exec("UPDATE server_devices SET last_seen=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), device.DeviceID)
	return device, true
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
