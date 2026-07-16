package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminCreateUserWeb(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "admin_create_user", webPage{Title: "admin.createUser", Admin: true})
	case http.MethodPost:
		if !s.requireAdminMutation(w, r) {
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/admin/create-user")
			return
		}
		username, email, password := strings.TrimSpace(r.FormValue("username")), strings.TrimSpace(r.FormValue("email")), r.FormValue("password")
		if username == "" || email == "" || password == "" {
			s.renderPage(w, r, "admin_create_user", webPage{Title: "admin.createUser", Admin: true, Flash: "error.allFieldsRequired"})
			return
		}
		if err := validatePassword(password); err != "" {
			s.renderPage(w, r, "admin_create_user", webPage{Title: "admin.createUser", Admin: true, Flash: "error.passwordInvalid"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			jsonInternalError(w, err)
			return
		}
		userID := hex.EncodeToString(id)
		if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES (?, ?, ?, ?, 1, ?)", userID, username, strings.ToLower(email), string(hash), time.Now().UTC().Format(time.RFC3339)); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderPage(w, r, "admin_create_user", webPage{Title: "admin.createUser", Admin: true, Flash: "error.accountTaken"})
				return
			}
			jsonInternalError(w, err)
			return
		}
		s.auditLog("user_created", userID, "", s.clientIP(r), "created by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAdminWeb(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	page := strings.TrimPrefix(r.URL.Path, "/admin/")
	if page == "" || page == "admin" {
		page = "dashboard"
	}
	allowed := map[string]bool{"dashboard": true, "users": true, "devices": true, "vaults": true, "storage": true, "audit": true, "settings": true, "diagnostics": true}
	if !allowed[page] {
		s.handleNotFound(w, r)
		return
	}
	stats, err := s.Stats(r.Context())
	if err != nil {
		log.Printf("admin stats: %v", err)
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/")
		return
	}
	data := webPage{Title: "admin." + page, Admin: true, AdminPage: page, Stats: stats, Health: s.healthStatus(r.Context())}
	switch page {
	case "users":
		data.AdminUsers, err = s.webAdminUsers()
	case "devices":
		data.AdminDevices, err = s.webAdminDevices()
	case "vaults":
		data.Vaults, err = s.webVaults()
	case "audit":
		data.Audit, err = s.webAudit()
	case "settings":
		data.SMTP = s.webSMTP()
	}
	if err != nil {
		log.Printf("admin %s: %v", page, err)
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/admin/dashboard")
		return
	}
	s.renderPage(w, r, "admin", data)
}

func (s *Server) webAdminUsers() ([]webAdminUser, error) {
	rows, err := s.db.Query(`SELECT u.id,u.username,u.email,u.confirmed,u.blocked,u.created_at,COALESCE(u.last_seen,''),COUNT(ud.device_id) FROM server_users u LEFT JOIN server_user_devices ud ON ud.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webAdminUser
	for rows.Next() {
		var u webAdminUser
		var confirmed, blocked int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &confirmed, &blocked, &u.CreatedAt, &u.LastSeen, &u.Devices); err != nil {
			return nil, err
		}
		u.Confirmed = confirmed != 0
		u.Blocked = blocked != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Server) webAdminDevices() ([]webAdminDevice, error) {
	rows, err := s.db.Query(`SELECT d.id,d.name,COALESCE(u.username,''),COALESCE(d.vault_id,''),COALESCE(d.client_version,''),COALESCE(d.last_seen,''),COALESCE(d.revoked_at,''),d.created_at FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id ORDER BY d.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webAdminDevice
	for rows.Next() {
		var d webAdminDevice
		var revoked string
		if err := rows.Scan(&d.ID, &d.Name, &d.User, &d.Vault, &d.Version, &d.LastSeen, &revoked, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Revoked = revoked != ""
		if d.LastSeen == "" {
			d.LastSeen = "—"
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Server) webVaults() ([]webVault, error) {
	rows, err := s.db.Query(`SELECT COALESCE(u.username,''),d.vault_id,COUNT(DISTINCT d.id),COUNT(o.op_id),COALESCE(MAX(d.last_seen),'') FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id LEFT JOIN server_ops o ON o.user_id=d.user_id AND o.vault_id=d.vault_id WHERE COALESCE(d.user_id,'')!='' AND COALESCE(d.vault_id,'')!='' GROUP BY d.user_id,d.vault_id ORDER BY MAX(d.last_seen) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webVault
	for rows.Next() {
		var v webVault
		if err := rows.Scan(&v.User, &v.Vault, &v.Devices, &v.Operations, &v.LastActivity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Server) webAudit() ([]webAudit, error) {
	rows, err := s.db.Query(`SELECT event_type,COALESCE(user_id,''),COALESCE(device_id,''),created_at FROM server_audit_log ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webAudit
	for rows.Next() {
		var a webAudit
		if err := rows.Scan(&a.Event, &a.User, &a.Device, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Server) webSMTP() webSMTP {
	return webSMTP{Host: s.smtpGet("smtp_host"), Port: s.smtpGet("smtp_port"), User: s.smtpGet("smtp_user"), Security: s.smtpGet("smtp_security"), From: s.smtpGet("smtp_from"), ServerURL: s.smtpGet("server_url")}
}

func (s *Server) adminReauth(r *http.Request, subject string) bool {
	return s.cfg.CheckAdmin(subject, r.FormValue("password"))
}

func (s *Server) handleAdminWebAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	session, ok := s.requireSession(w, r, sessionScopeAdmin)
	if !ok || !s.verifyCSRF(w, r, session) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/admin/dashboard")
		return
	}
	action := r.FormValue("action")
	switch action {
	case "toggle-user":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/users")
			return
		}
		id := r.FormValue("id")
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		var blocked int
		if err := tx.QueryRow("SELECT blocked FROM server_users WHERE id=?", id).Scan(&blocked); err != nil {
			if err == sql.ErrNoRows {
				s.renderWebError(w, r, http.StatusNotFound, "error.badRequest", "/admin/users")
				return
			}
			jsonInternalError(w, err)
			return
		}
		newValue := 1
		if blocked != 0 {
			newValue = 0
		}
		if _, err := tx.Exec("UPDATE server_users SET blocked=? WHERE id=?", newValue, id); err != nil {
			jsonInternalError(w, err)
			return
		}
		if newValue != 0 {
			if _, err := tx.Exec("DELETE FROM server_sessions WHERE scope='user' AND subject_id=?", id); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("user_block_changed", id, "", s.clientIP(r), "changed by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case "edit-user":
		id, username, email := r.FormValue("id"), strings.TrimSpace(r.FormValue("username")), strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if id == "" || username == "" || email == "" {
			s.renderWebError(w, r, http.StatusBadRequest, "error.allFieldsRequired", "/admin/users")
			return
		}
		if _, err := s.db.Exec("UPDATE server_users SET username=?, email=? WHERE id=?", username, email, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderWebError(w, r, http.StatusConflict, "error.accountTaken", "/admin/users")
				return
			}
			jsonInternalError(w, err)
			return
		}
		s.auditLog("user_updated", id, "", s.clientIP(r), "updated by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case "reset-user-password":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/users")
			return
		}
		id, password := r.FormValue("id"), r.FormValue("new_password")
		if err := validatePassword(password); err != "" {
			s.renderWebError(w, r, http.StatusBadRequest, "error.passwordInvalid", "/admin/users")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		if _, err := tx.Exec("UPDATE server_users SET password_hash=? WHERE id=?", string(hash), id); err != nil {
			jsonInternalError(w, err)
			return
		}
		if _, err := tx.Exec("DELETE FROM server_sessions WHERE scope='user' AND subject_id=?", id); err != nil {
			jsonInternalError(w, err)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("user_password_reset", id, "", s.clientIP(r), "reset by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case "delete-user":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/users")
			return
		}
		id := r.FormValue("id")
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		for _, statement := range []string{"DELETE FROM server_sessions WHERE subject_id=? AND scope='user'", "DELETE FROM server_email_tokens WHERE user_id=?", "DELETE FROM server_blob_refs WHERE user_id=?", "DELETE FROM server_idempotency_keys WHERE user_id=?", "DELETE FROM server_tombstones WHERE user_id=?", "DELETE FROM server_revisions WHERE op_id IN (SELECT op_id FROM server_ops WHERE user_id=?)", "DELETE FROM server_ops WHERE user_id=?", "DELETE FROM server_user_devices WHERE user_id=?", "DELETE FROM server_devices WHERE user_id=?", "DELETE FROM server_audit_log WHERE user_id=?", "DELETE FROM server_users WHERE id=?"} {
			if _, err := tx.Exec(statement, id); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("user_deleted", id, "", s.clientIP(r), "deleted by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case "revoke-device":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/devices")
			return
		}
		id := r.FormValue("id")
		if err := s.revokeDevice(id, time.Now().UTC().Format(time.RFC3339)); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("device_revoked", "", id, s.clientIP(r), "revoked by administrator")
		http.Redirect(w, r, "/admin/devices", http.StatusSeeOther)
	case "smtp":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/settings")
			return
		}
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		for _, key := range []string{"smtp_host", "smtp_port", "smtp_user", "smtp_security", "smtp_from", "server_url"} {
			if _, err := tx.Exec("INSERT OR REPLACE INTO server_smtp_config (key, value) VALUES (?, ?)", key, r.FormValue(key)); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if pass := r.FormValue("smtp_pass"); pass != "" {
			if _, err := tx.Exec("INSERT OR REPLACE INTO server_smtp_config (key, value) VALUES (?, ?)", "smtp_pass", pass); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("smtp_settings_updated", "", "", s.clientIP(r), "updated by administrator")
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
	default:
		s.renderWebError(w, r, http.StatusBadRequest, "error.badRequest", "/admin/dashboard")
	}
}

func (s *Server) handleAdminWebLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	if cookie, err := r.Cookie("admin_session"); err == nil {
		if err := s.deleteSession(cookie.Value); err != nil {
			jsonInternalError(w, err)
			return
		}
	}
	s.clearSessionCookies(w, r, sessionScopeAdmin)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
