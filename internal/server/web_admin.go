package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type oneTimeWebSecret struct {
	Value     string
	ExpiresAt time.Time
}

// storeAdminOneTimeSecret keeps a generated password only long enough for the
// currently authenticated administrator to retrieve it once. It is never
// written to the database, URL, audit log, or cookie.
func (s *Server) storeAdminOneTimeSecret(sessionToken, secret string) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	now := time.Now().UTC()
	for key, value := range s.webSecrets {
		if !now.Before(value.ExpiresAt) {
			delete(s.webSecrets, key)
		}
	}
	s.webSecrets[sha256Hex(sessionToken)] = oneTimeWebSecret{Value: secret, ExpiresAt: now.Add(5 * time.Minute)}
}

func (s *Server) takeAdminOneTimeSecret(sessionToken string) string {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	key := sha256Hex(sessionToken)
	value, ok := s.webSecrets[key]
	delete(s.webSecrets, key)
	if !ok || !time.Now().UTC().Before(value.ExpiresAt) {
		return ""
	}
	return value.Value
}

func (s *Server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminPasswordResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	s.renderPage(w, r, "admin_password_result", webPage{Title: "admin.resetPassword", Admin: true, AdminPage: "users"})
}

func (s *Server) handleAdminPasswordResultSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		jsonErrCode(w, http.StatusForbidden, "session_invalid", "administrator session is required")
		return
	}
	secret := s.takeAdminOneTimeSecret(cookie.Value)
	if secret == "" {
		jsonErrCode(w, http.StatusGone, "one_time_secret_expired", "one-time password is no longer available")
		return
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	jsonOK(w, map[string]string{"password": secret})
}

func (s *Server) handleAdminVaultDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	userID, vaultID := r.URL.Query().Get("user"), r.URL.Query().Get("vault")
	if userID == "" || vaultID == "" {
		s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/admin/vaults")
		return
	}
	var d webVaultDetail
	if err := s.db.QueryRow(`SELECT COALESCE((SELECT username FROM server_users WHERE id=?),''), COUNT(DISTINCT d.id), COUNT(DISTINCT CASE WHEN COALESCE(d.revoked_at,'')='' THEN d.id END), COUNT(DISTINCT CASE WHEN COALESCE(d.revoked_at,'')!='' THEN d.id END), COUNT(DISTINCT o.op_id), COALESCE(MAX(o.server_sequence),0), COALESCE(MAX(d.last_seen),'') FROM server_devices d LEFT JOIN server_ops o ON o.user_id=d.user_id AND o.vault_id=d.vault_id WHERE d.user_id=? AND d.vault_id=?`, userID, userID, vaultID).Scan(&d.User, &d.Devices, &d.Active, &d.Revoked, &d.Operations, &d.Sequence, &d.LastActivity); err != nil {
		jsonInternalError(w, err)
		return
	}
	d.Vault = vaultID
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(size),0) FROM server_blob_refs WHERE user_id=? AND vault_id=?`, userID, vaultID).Scan(&d.BlobBytes); err != nil {
		jsonInternalError(w, err)
		return
	}
	rows, err := s.db.Query(`SELECT d.id,d.name,COALESCE(u.username,''),COALESCE(d.vault_id,''),COALESCE(d.client_version,''),COALESCE(d.last_ip,''),COALESCE(d.last_seen,''),COALESCE(d.revoked_at,''),d.created_at,COALESCE(d.token_prefix,''),COALESCE(d.token_suffix,'') FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id WHERE d.user_id=? AND d.vault_id=? ORDER BY d.created_at DESC`, userID, vaultID)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer rows.Close()
	var devices []webAdminDevice
	for rows.Next() {
		var device webAdminDevice
		var revoked, prefix, suffix string
		if err := rows.Scan(&device.ID, &device.Name, &device.User, &device.Vault, &device.Version, &device.LastIP, &device.LastSeen, &revoked, &device.CreatedAt, &prefix, &suffix); err != nil {
			jsonInternalError(w, err)
			return
		}
		device.Revoked = revoked != ""
		if prefix != "" || suffix != "" {
			device.TokenHint = prefix + "…" + suffix
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		jsonInternalError(w, err)
		return
	}
	s.renderPage(w, r, "vault_detail", webPage{Title: "admin.vaults", Admin: true, AdminPage: "vaults", VaultDetail: d, VaultDevices: devices})
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
	case "dashboard":
		data.Audit, _, err = s.webAudit(webList{Page: 1, PerPage: 5})
		if err == nil {
			data.AdminDevices, _, err = s.webAdminDevices(webList{Page: 1, PerPage: 5})
		}
		if !data.Health.DatabaseReachable || !data.Health.BlobStorageWritable {
			data.Warnings = append(data.Warnings, "admin.warningReadiness")
		}
		if s.smtpGet("smtp_host") == "" {
			data.Warnings = append(data.Warnings, "admin.warningSMTP")
		}
		if stats.Operations > 100000 {
			data.Warnings = append(data.Warnings, "admin.warningOperations")
		}
	case "users":
		data.List = webListFromRequest(r)
		data.AdminUsers, data.List, err = s.webAdminUsers(data.List)
	case "devices":
		data.List = webListFromRequest(r)
		data.AdminDevices, data.List, err = s.webAdminDevices(data.List)
	case "vaults":
		data.Vaults, err = s.webVaults()
	case "audit":
		data.List = webListFromRequest(r)
		data.Audit, data.List, err = s.webAudit(data.List)
	case "settings":
		data.SMTP = s.webSMTP()
		switch r.URL.Query().Get("flash") {
		case "settings_saved":
			data.Flash = "admin.settingsSaved"
		case "smtp_saved":
			data.Flash = "admin.smtpSaved"
		case "smtp_test_passed":
			data.Flash = "admin.smtpPassed"
		case "smtp_test_failed":
			data.Flash = "admin.smtpTestFailed"
		}
	case "storage":
		if r.URL.Query().Get("flash") == "cleanup_done" {
			data.Flash = "admin.cleanupDone"
		}
	}
	if err != nil {
		log.Printf("admin %s: %v", page, err)
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/admin/dashboard")
		return
	}
	s.renderPage(w, r, "admin_"+page, data)
}

func webListFromRequest(r *http.Request) webList {
	trim := func(value string) string {
		value = strings.TrimSpace(value)
		if len(value) > 160 {
			return value[:160]
		}
		return value
	}
	list := webList{Query: trim(r.URL.Query().Get("q")), Status: trim(r.URL.Query().Get("status")), Sort: trim(r.URL.Query().Get("sort")), User: trim(r.URL.Query().Get("user")), Vault: trim(r.URL.Query().Get("vault")), Version: trim(r.URL.Query().Get("version")), Event: trim(r.URL.Query().Get("event")), Severity: trim(r.URL.Query().Get("severity")), Page: 1, PerPage: 25}
	if value, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && value > 0 {
		list.Page = value
	}
	if value, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && value > 0 && value <= 100 {
		list.PerPage = value
	}
	return list
}

func finishWebList(list webList, total int) webList {
	list.Total = total
	list.Pages = (total + list.PerPage - 1) / list.PerPage
	if list.Pages == 0 {
		list.Pages = 1
	}
	if list.Page > list.Pages {
		list.Page = list.Pages
	}
	if list.Page > 1 {
		list.Previous = list.Page - 1
	}
	if list.Page < list.Pages {
		list.Next = list.Page + 1
	}
	return list
}

func (s *Server) webAdminUsers(list webList) ([]webAdminUser, webList, error) {
	where := ""
	args := []interface{}{}
	if list.Query != "" {
		where = " WHERE (u.username LIKE ? OR u.email LIKE ?)"
		like := "%" + list.Query + "%"
		args = append(args, like, like)
	}
	if list.Status == "active" || list.Status == "blocked" || list.Status == "unconfirmed" {
		condition := map[string]string{"active": "u.confirmed=1 AND u.blocked=0", "blocked": "u.blocked=1", "unconfirmed": "u.confirmed=0"}[list.Status]
		if where == "" {
			where = " WHERE " + condition
		} else {
			where += " AND " + condition
		}
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_users u"+where, args...).Scan(&total); err != nil {
		return nil, list, err
	}
	list = finishWebList(list, total)
	order := map[string]string{"username": "u.username COLLATE NOCASE ASC", "last_seen": "COALESCE(u.last_seen,'') DESC", "created": "u.created_at DESC"}[list.Sort]
	if order == "" {
		list.Sort = "created"
		order = "u.created_at DESC"
	}
	queryArgs := append([]interface{}{}, args...)
	queryArgs = append(queryArgs, list.PerPage, (list.Page-1)*list.PerPage)
	rows, err := s.db.Query(`SELECT u.id,u.username,u.email,u.confirmed,u.blocked,u.created_at,COALESCE(u.last_seen,''),COUNT(ud.device_id),(SELECT COUNT(DISTINCT vd.vault_id) FROM server_devices vd WHERE vd.user_id=u.id AND COALESCE(vd.vault_id,'')!='') FROM server_users u LEFT JOIN server_user_devices ud ON ud.user_id=u.id`+where+` GROUP BY u.id ORDER BY `+order+` LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, list, err
	}
	defer rows.Close()
	var out []webAdminUser
	for rows.Next() {
		var u webAdminUser
		var confirmed, blocked int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &confirmed, &blocked, &u.CreatedAt, &u.LastSeen, &u.Devices, &u.Vaults); err != nil {
			return nil, list, err
		}
		u.Confirmed = confirmed != 0
		u.Blocked = blocked != 0
		out = append(out, u)
	}
	return out, list, rows.Err()
}

func (s *Server) webAdminDevices(list webList) ([]webAdminDevice, webList, error) {
	where := ""
	args := []interface{}{}
	addCondition := func(condition string, values ...interface{}) {
		if where == "" {
			where = " WHERE " + condition
		} else {
			where += " AND " + condition
		}
		args = append(args, values...)
	}
	if list.Query != "" {
		like := "%" + list.Query + "%"
		addCondition("(d.name LIKE ? OR u.username LIKE ? OR d.vault_id LIKE ?)", like, like, like)
	}
	if list.Status == "active" || list.Status == "revoked" {
		condition := map[string]string{"active": "COALESCE(d.revoked_at,'')=''", "revoked": "COALESCE(d.revoked_at,'')!=''"}[list.Status]
		addCondition(condition)
	}
	if list.User != "" {
		addCondition("u.username LIKE ?", "%"+list.User+"%")
	}
	if list.Vault != "" {
		addCondition("d.vault_id LIKE ?", "%"+list.Vault+"%")
	}
	if list.Version != "" {
		addCondition("d.client_version LIKE ?", "%"+list.Version+"%")
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id`+where, args...).Scan(&total); err != nil {
		return nil, list, err
	}
	list = finishWebList(list, total)
	order := map[string]string{"name": "d.name COLLATE NOCASE ASC", "last_seen": "COALESCE(d.last_seen,'') DESC", "created": "d.created_at DESC"}[list.Sort]
	if order == "" {
		list.Sort = "created"
		order = "d.created_at DESC"
	}
	queryArgs := append([]interface{}{}, args...)
	queryArgs = append(queryArgs, list.PerPage, (list.Page-1)*list.PerPage)
	rows, err := s.db.Query(`SELECT d.id,d.name,COALESCE(u.username,''),COALESCE(d.vault_id,''),COALESCE(d.client_version,''),COALESCE(d.last_ip,''),COALESCE(d.last_seen,''),COALESCE(d.revoked_at,''),d.created_at,COALESCE(d.token_prefix,''),COALESCE(d.token_suffix,'') FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id`+where+` ORDER BY `+order+` LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, list, err
	}
	defer rows.Close()
	var out []webAdminDevice
	for rows.Next() {
		var d webAdminDevice
		var revoked, prefix, suffix string
		if err := rows.Scan(&d.ID, &d.Name, &d.User, &d.Vault, &d.Version, &d.LastIP, &d.LastSeen, &revoked, &d.CreatedAt, &prefix, &suffix); err != nil {
			return nil, list, err
		}
		if prefix != "" || suffix != "" {
			d.TokenHint = prefix + "…" + suffix
		}
		d.Revoked = revoked != ""
		if d.LastSeen == "" {
			d.LastSeen = "—"
		}
		out = append(out, d)
	}
	return out, list, rows.Err()
}

func (s *Server) webVaults() ([]webVault, error) {
	rows, err := s.db.Query(`SELECT COALESCE(u.username,''),d.user_id,d.vault_id,COUNT(DISTINCT d.id),COUNT(o.op_id),COALESCE(MAX(d.last_seen),'') FROM server_devices d LEFT JOIN server_users u ON u.id=d.user_id LEFT JOIN server_ops o ON o.user_id=d.user_id AND o.vault_id=d.vault_id WHERE COALESCE(d.user_id,'')!='' AND COALESCE(d.vault_id,'')!='' GROUP BY d.user_id,d.vault_id ORDER BY MAX(d.last_seen) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webVault
	for rows.Next() {
		var v webVault
		if err := rows.Scan(&v.User, &v.UserID, &v.Vault, &v.Devices, &v.Operations, &v.LastActivity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Server) webAudit(list webList) ([]webAudit, webList, error) {
	where := ""
	args := []interface{}{}
	addCondition := func(condition string, values ...interface{}) {
		if where == "" {
			where = " WHERE " + condition
		} else {
			where += " AND " + condition
		}
		args = append(args, values...)
	}
	if list.Query != "" {
		like := "%" + list.Query + "%"
		addCondition("(a.event_type LIKE ? OR a.user_id LIKE ? OR a.device_id LIKE ?)", like, like, like)
	}
	if list.Event != "" {
		addCondition("a.event_type LIKE ?", "%"+list.Event+"%")
	}
	if list.User != "" {
		addCondition("a.user_id LIKE ?", "%"+list.User+"%")
	}
	if list.Severity == "error" {
		addCondition("(a.event_type LIKE '%failed%' OR a.event_type LIKE '%error%')")
	} else if list.Severity == "warning" {
		addCondition("a.event_type LIKE '%rate_limit%'")
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_audit_log a"+where, args...).Scan(&total); err != nil {
		return nil, list, err
	}
	list = finishWebList(list, total)
	queryArgs := append([]interface{}{}, args...)
	queryArgs = append(queryArgs, list.PerPage, (list.Page-1)*list.PerPage)
	rows, err := s.db.Query(`SELECT a.event_type,COALESCE(u.username,a.user_id,''),COALESCE(d.name,a.device_id,''),COALESCE(a.ip,''),COALESCE(a.message,''),a.created_at FROM server_audit_log a LEFT JOIN server_users u ON u.id=a.user_id LEFT JOIN server_devices d ON d.id=a.device_id`+where+` ORDER BY a.id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, list, err
	}
	defer rows.Close()
	var out []webAudit
	for rows.Next() {
		var a webAudit
		if err := rows.Scan(&a.Event, &a.User, &a.Device, &a.IP, &a.Message, &a.At); err != nil {
			return nil, list, err
		}
		a.Severity = auditSeverity(a.Event)
		out = append(out, a)
	}
	return out, list, rows.Err()
}

func auditSeverity(event string) string {
	if strings.Contains(event, "failed") || strings.Contains(event, "error") {
		return "error"
	}
	if strings.Contains(event, "rate_limit") || strings.Contains(event, "revoked") || strings.Contains(event, "blocked") {
		return "warning"
	}
	return "info"
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
	case "web-settings":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/settings")
			return
		}
		locale := r.FormValue("default_locale")
		if locale != "ru" && locale != "en" {
			locale = "en"
		}
		publicURL := strings.TrimRight(strings.TrimSpace(r.FormValue("public_url")), "/")
		if publicURL != "" {
			parsed, err := url.ParseRequestURI(publicURL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				s.renderWebError(w, r, http.StatusBadRequest, "error.invalidPublicURL", "/admin/settings")
				return
			}
		}
		s.cfg.mu.Lock()
		s.cfg.Web.DefaultLocale = locale
		s.cfg.Web.AllowRegistration = r.FormValue("allow_registration") == "on"
		s.cfg.Web.ServerName = strings.TrimSpace(r.FormValue("server_name"))
		s.cfg.PublicURL = publicURL
		err := s.cfg.saveLocked()
		s.cfg.mu.Unlock()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("web_settings_updated", "", "", s.clientIP(r), "updated by administrator")
		http.Redirect(w, r, "/admin/settings?flash=settings_saved", http.StatusSeeOther)
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
	case "confirm-user":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/users")
			return
		}
		id := r.FormValue("id")
		result, err := s.db.Exec("UPDATE server_users SET confirmed=1 WHERE id=?", id)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		if changed, err := result.RowsAffected(); err != nil || changed == 0 {
			if err != nil {
				jsonInternalError(w, err)
			} else {
				s.renderWebError(w, r, http.StatusNotFound, "error.badRequest", "/admin/users")
			}
			return
		}
		s.auditLog("user_confirmed", id, "", s.clientIP(r), "confirmed by administrator")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	case "reset-user-password":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/users")
			return
		}
		id := r.FormValue("id")
		password, err := randomSecret(16)
		if err != nil {
			jsonInternalError(w, err)
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
		cookie, err := r.Cookie("admin_session")
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		s.storeAdminOneTimeSecret(cookie.Value, password)
		http.Redirect(w, r, "/admin/password-result", http.StatusSeeOther)
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
	case "delete-device":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/devices")
			return
		}
		id := r.FormValue("id")
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		var revoked string
		if err := tx.QueryRow("SELECT COALESCE(revoked_at,'') FROM server_devices WHERE id=?", id).Scan(&revoked); err != nil {
			if err == sql.ErrNoRows {
				s.renderWebError(w, r, http.StatusNotFound, "error.badRequest", "/admin/devices")
			} else {
				jsonInternalError(w, err)
			}
			return
		}
		if revoked == "" {
			s.renderWebError(w, r, http.StatusConflict, "error.deviceMustBeRevoked", "/admin/devices")
			return
		}
		for _, statement := range []string{"DELETE FROM server_user_devices WHERE device_id=?", "DELETE FROM server_devices WHERE id=?"} {
			if _, err := tx.Exec(statement, id); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("device_deleted", "", id, s.clientIP(r), "revoked device deleted by administrator")
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
		http.Redirect(w, r, "/admin/settings?flash=smtp_saved", http.StatusSeeOther)
	case "smtp-test":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/settings")
			return
		}
		smtp := s.webSMTP()
		to := strings.TrimSpace(r.FormValue("test_to"))
		if to == "" {
			to = smtp.From
		}
		if smtp.Host == "" || smtp.Port == "" || smtp.From == "" || to == "" {
			http.Redirect(w, r, "/admin/settings?flash=smtp_test_failed", http.StatusSeeOther)
			return
		}
		if err := s.smtpTest(smtp.Host, smtp.Port, smtp.User, s.smtpGet("smtp_pass"), smtp.Security, smtp.From, to); err != nil {
			log.Printf("admin SMTP test failed: %v", err)
			s.auditLog("smtp_test_failed", "", "", s.clientIP(r), "tested by administrator")
			http.Redirect(w, r, "/admin/settings?flash=smtp_test_failed", http.StatusSeeOther)
			return
		}
		s.auditLog("smtp_test_passed", "", "", s.clientIP(r), "tested by administrator")
		http.Redirect(w, r, "/admin/settings?flash=smtp_test_passed", http.StatusSeeOther)
	case "cleanup":
		if !s.adminReauth(r, session.SubjectID) {
			s.renderWebError(w, r, http.StatusForbidden, "error.invalidCredentials", "/admin/storage")
			return
		}
		if err := s.CleanupRetention(time.Now().UTC()); err != nil {
			jsonInternalError(w, err)
			return
		}
		s.auditLog("retention_cleanup", "", "", s.clientIP(r), "safe retention cleanup run by administrator")
		http.Redirect(w, r, "/admin/storage?flash=cleanup_done", http.StatusSeeOther)
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

// handleAdminDiagnosticsJSON is intentionally a separate, authenticated
// download: it contains operational state but never paths, credentials,
// tokens, payloads, or user content.
func (s *Server) handleAdminDiagnosticsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	stats, err := s.Stats(r.Context())
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]interface{}{
		"health": s.healthStatus(r.Context()),
		"stats":  stats,
		"limits": map[string]interface{}{
			"max_json_body":       s.cfg.Limits.MaxJSONBody,
			"max_push_operations": s.cfg.Limits.MaxPushOperations,
			"max_pull_page":       s.cfg.Limits.MaxPullPage,
			"max_blob_bytes":      s.cfg.Limits.MaxBlobBytes,
		},
		"web": map[string]interface{}{
			"default_locale":       s.cfg.Web.DefaultLocale,
			"registration_allowed": s.cfg.Web.AllowRegistration,
		},
	})
}
