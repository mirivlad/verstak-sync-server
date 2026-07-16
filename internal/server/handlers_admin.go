package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.renderPage(w, r, "admin_login", webPage{Title: "admin.loginTitle", Admin: true})
	case "POST":
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/admin/login")
			return
		}
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if !s.allowRate(w, r, "login", user) {
			return
		}
		if !s.cfg.CheckAdmin(user, pass) {
			s.renderPageStatus(w, r, "admin_login", webPage{Title: "admin.loginTitle", Admin: true, Flash: "error.invalidCredentials"}, http.StatusUnauthorized)
			return
		}
		tok, csrf, err := s.createSession(sessionScopeAdmin, user)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		s.setSessionCookies(w, r, sessionScopeAdmin, tok, csrf)
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) requireAdminCookie(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.requireSession(w, r, sessionScopeAdmin)
	return ok
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
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
	jsonOK(w, stats)
}

func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	var req struct {
		Host     string `json:"smtp_host"`
		Port     string `json:"smtp_port"`
		User     string `json:"smtp_user"`
		Pass     string `json:"smtp_pass"`
		Security string `json:"smtp_security"`
		From     string `json:"smtp_from"`
		To       string `json:"test_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "bad json")
		return
	}
	host := req.Host
	port := req.Port
	user := req.User
	pass := req.Pass
	security := req.Security
	from := req.From
	to := req.To
	if to == "" {
		to = from
	}
	if host == "" || port == "" || from == "" {
		jsonOK(w, map[string]interface{}{"ok": false, "error": t(s.locale(), "admin.smtpRequired")})
		return
	}
	if err := s.smtpTest(host, port, user, pass, security, from, to); err != nil {
		log.Printf("admin SMTP test failed: %v", err)
		jsonOK(w, map[string]interface{}{"ok": false, "error": t(s.locale(), "admin.smtpTestFailed")})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true})
}

func (s *Server) handleAdminAPIDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	rows, err := s.db.Query(`
		SELECT d.id, d.name, d.client_version, COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at,
		       COALESCE(u.username,'')
		FROM server_devices d
		LEFT JOIN server_users u ON u.id = d.user_id
		ORDER BY d.created_at DESC`)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer rows.Close()
	type devDTO struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		ClientVersion string `json:"client_version"`
		LastSeen      string `json:"last_seen"`
		RevokedAt     string `json:"revoked_at"`
		CreatedAt     string `json:"created_at"`
		User          string `json:"user"`
	}
	var out []devDTO
	for rows.Next() {
		var d devDTO
		rows.Scan(&d.ID, &d.Name, &d.ClientVersion, &d.LastSeen, &d.RevokedAt, &d.CreatedAt, &d.User)
		out = append(out, d)
	}
	jsonOK(w, out)
}

func (s *Server) handleAdminAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	switch r.Method {
	case "GET":
		rows, err := s.db.Query("SELECT id, name, COALESCE(token_prefix,''), COALESCE(token_suffix,'') FROM server_devices ORDER BY created_at")
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer rows.Close()
		var out []map[string]string
		for rows.Next() {
			var id, name, prefix, suffix string
			if err := rows.Scan(&id, &name, &prefix, &suffix); err != nil {
				jsonInternalError(w, err)
				return
			}
			out = append(out, map[string]string{"id": id, "name": name, "token_hint": prefix + "…" + suffix})
		}
		jsonOK(w, out)
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleAdminAPISmtp(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonErr(w, 400, "bad form")
		return
	}
	for _, key := range []string{"smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_security", "smtp_from", "server_url"} {
		val := r.FormValue(key)
		if val != "" {
			s.smtpSet(key, val)
		}
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminAPIKeysDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		methodNotAllowed(w, "DELETE")
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/keys/")
	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM server_user_devices WHERE device_id=?", id); err != nil {
		jsonInternalError(w, err)
		return
	}
	if _, err := tx.Exec("DELETE FROM server_devices WHERE id=?", id); err != nil {
		jsonInternalError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleAdminAPIUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.requireAdminCookie(w, r) {
		return
	}
	filter := r.URL.Query().Get("filter")
	sort := r.URL.Query().Get("sort")
	order := r.URL.Query().Get("order")
	page := 1
	perPage := 20
	if v := r.URL.Query().Get("page"); v != "" {
		fmt.Sscanf(v, "%d", &page)
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		fmt.Sscanf(v, "%d", &perPage)
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	where := ""
	var args []interface{}
	if filter != "" {
		where = " WHERE u.username LIKE ?"
		args = append(args, "%"+filter+"%")
	}
	validSorts := map[string]string{
		"username":   "u.username",
		"email":      "u.email",
		"confirmed":  "u.confirmed",
		"blocked":    "u.blocked",
		"created_at": "u.created_at",
		"last_seen":  "u.last_seen",
		"devices":    "devices",
	}
	orderClause := "u.created_at DESC"
	if col, ok := validSorts[sort]; ok {
		if order != "asc" {
			order = "desc"
		}
		orderClause = col + " " + order
	}
	var total int
	countSQL := "SELECT COUNT(*) FROM server_users u" + where
	s.db.QueryRow(countSQL, args...).Scan(&total)
	offset := (page - 1) * perPage
	sql := `SELECT u.id, u.username, u.email, u.confirmed, u.blocked, u.last_seen, u.created_at,
		COALESCE((SELECT COUNT(*) FROM server_user_devices ud JOIN server_devices d ON d.id=ud.device_id WHERE ud.user_id=u.id),0) AS devices
		FROM server_users u` + where + ` ORDER BY ` + orderClause + ` LIMIT ? OFFSET ?`
	args = append(args, perPage, offset)
	rows, err := s.db.Query(sql, args...)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer rows.Close()
	type userRow struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		Confirmed int    `json:"confirmed"`
		Blocked   int    `json:"blocked"`
		LastSeen  string `json:"last_seen"`
		CreatedAt string `json:"created_at"`
		Devices   int    `json:"devices"`
	}
	var users []userRow
	for rows.Next() {
		var u userRow
		var lastSeen *string
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Confirmed, &u.Blocked, &lastSeen, &u.CreatedAt, &u.Devices)
		if lastSeen != nil {
			u.LastSeen = *lastSeen
		}
		users = append(users, u)
	}
	jsonOK(w, map[string]interface{}{
		"users":    users,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

func (s *Server) handleAdminAPIUserActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		methodNotAllowed(w, "POST", "DELETE")
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")

	if strings.HasSuffix(path, "/block") && r.Method == "POST" {
		id := strings.TrimSuffix(path, "/block")
		id = strings.TrimSuffix(id, "/")
		var blocked int
		if err := s.db.QueryRow("SELECT blocked FROM server_users WHERE id=?", id).Scan(&blocked); err != nil {
			jsonErr(w, http.StatusNotFound, "user not found")
			return
		}
		newVal := 1
		if blocked != 0 {
			newVal = 0
		}
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		if _, err := tx.Exec("UPDATE server_users SET blocked=? WHERE id=?", newVal, id); err != nil {
			jsonInternalError(w, err)
			return
		}
		if newVal != 0 {
			if _, err := tx.Exec("DELETE FROM server_sessions WHERE scope='user' AND subject_id=?", id); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		jsonOK(w, map[string]interface{}{"status": "ok", "blocked": newVal})
		return
	}
	if strings.HasSuffix(path, "/reset-password") && r.Method == "POST" {
		if !s.allowRate(w, r, "admin-reset", "") {
			return
		}
		id := strings.TrimSuffix(path, "/reset-password")
		id = strings.TrimSuffix(id, "/")
		b := make([]byte, 12)
		rand.Read(b)
		newPass := hex.EncodeToString(b)
		hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		_, err = s.db.Exec("UPDATE server_users SET password_hash=? WHERE id=?", string(hash), id)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		jsonOK(w, map[string]interface{}{"status": "ok", "new_password": newPass})
		return
	}
	if strings.HasSuffix(path, "/edit") && r.Method == "POST" {
		id := strings.TrimSuffix(path, "/edit")
		id = strings.TrimSuffix(id, "/")
		var editReq struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}
		if !decodeJSONBody(w, r, &editReq, s.cfg.Limits.MaxJSONBody) {
			return
		}
		if editReq.Username == "" || editReq.Email == "" {
			jsonErr(w, 400, "username and email required")
			return
		}
		_, err := s.db.Exec("UPDATE server_users SET username=?, email=? WHERE id=?", editReq.Username, strings.ToLower(editReq.Email), id)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		jsonOK(w, map[string]interface{}{"status": "ok"})
		return
	}
	if r.Method == "DELETE" {
		id := strings.TrimSuffix(path, "/")
		tx, err := s.db.Begin()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		defer tx.Rollback()
		for _, statement := range []string{
			"DELETE FROM server_sessions WHERE subject_id=? AND scope='user'",
			"DELETE FROM server_email_tokens WHERE user_id=?",
			"DELETE FROM server_blob_refs WHERE user_id=?",
			"DELETE FROM server_idempotency_keys WHERE user_id=?",
			"DELETE FROM server_tombstones WHERE user_id=?",
			"DELETE FROM server_revisions WHERE op_id IN (SELECT op_id FROM server_ops WHERE user_id=?)",
			"DELETE FROM server_ops WHERE user_id=?",
			"DELETE FROM server_user_devices WHERE user_id=?",
			"DELETE FROM server_devices WHERE user_id=?",
			"DELETE FROM server_audit_log WHERE user_id=?",
			"DELETE FROM server_users WHERE id=?",
		} {
			if _, err := tx.Exec(statement, id); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonInternalError(w, err)
			return
		}
		jsonOK(w, map[string]interface{}{"status": "deleted"})
		return
	}
	jsonErr(w, 404, "unknown action")
}

func (s *Server) handleAdminAPICreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}
	if !s.requireAdminMutation(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "bad json")
		return
	}
	if req.Username == "" || req.Email == "" || req.Password == "" {
		jsonErr(w, 400, "username, email and password required")
		return
	}
	if err := validatePassword(req.Password); err != "" {
		jsonErr(w, 400, string(err))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, 500, "internal error")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	id := make([]byte, 12)
	rand.Read(id)
	userID := hex.EncodeToString(id)
	_, err = s.db.Exec(
		"INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 1, ?)",
		userID, req.Username, strings.ToLower(req.Email), string(hash), now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonErr(w, 409, "username or email already taken")
		} else {
			jsonInternalError(w, err)
		}
		return
	}
	jsonOK(w, map[string]string{"status": "ok", "user_id": userID})
}

var _ = time.Now
var _ = rand.Read
var _ = hex.EncodeToString
