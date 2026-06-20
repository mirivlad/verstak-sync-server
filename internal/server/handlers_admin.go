package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#16213e;padding:2rem;border-radius:8px;border:1px solid #0f3460;width:300px}
h2{margin:0 0 1rem;color:#e0e0f0}label{display:block;color:#a0a0b8;font-size:0.85rem;margin-bottom:0.35rem}
input{width:100%;background:#0f3460;border:1px solid #1a3a5c;color:#e0e0f0;padding:8px 10px;border-radius:4px;font-size:0.85rem;box-sizing:border-box;margin-bottom:0.75rem}
button{background:#4ecca3;color:#1a1a2e;border:none;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;font-weight:600;width:100%}</style></head>
<body><form method="POST"><h2>Admin Login</h2>
<label>Username</label><input name="username" required>
<label>Password</label><input type="password" name="password" required>
<button type="submit">Login</button></form></body></html>`))
	case "POST":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if !s.cfg.CheckAdmin(user, pass) {
			http.Error(w, "401 Unauthorized", 401)
			return
		}
		tok := s.tokens.Create()
		http.SetCookie(w, &http.Cookie{
			Name: "admin_session", Value: tok, Path: "/admin",
			HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400,
		})
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}

	var userCount, deviceCount, opsCount int
	s.db.QueryRow("SELECT COUNT(*) FROM server_users").Scan(&userCount)
	s.db.QueryRow("SELECT COUNT(*) FROM server_devices").Scan(&deviceCount)
	s.db.QueryRow("SELECT COUNT(*) FROM server_ops").Scan(&opsCount)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Dashboard</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0f0;margin:0;padding:2rem}
h1{color:#4ecca3}table{width:100%;border-collapse:collapse;margin:1rem 0}
th{text-align:left;padding:0.5rem;border-bottom:1px solid #0f3460;color:#a0a0b8}
td{padding:0.5rem;border-bottom:1px solid #0f3460}.stat{display:inline-block;background:#16213e;padding:1rem 1.5rem;border-radius:8px;margin:0.5rem;border:1px solid #0f3460}
.stat-num{font-size:1.5rem;color:#4ecca3;font-weight:600}.stat-label{color:#a0a0b8;font-size:0.85rem}
a{color:#4ecca3}</style></head><body>
<h1>Verstak Sync Server — Admin</h1>
<div class="stat"><div class="stat-num">` + intToStr(userCount) + `</div><div class="stat-label">Users</div></div>
<div class="stat"><div class="stat-num">` + intToStr(deviceCount) + `</div><div class="stat-label">Devices</div></div>
<div class="stat"><div class="stat-num">` + intToStr(opsCount) + `</div><div class="stat-label">Sync Ops</div></div>
<h2><a href="/admin/users">Users</a> | <a href="/admin/devices">Devices</a> | <a href="/api/v1/health">Health</a></h2>
</body></html>`))
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	rows, err := s.db.Query("SELECT id, username, email, confirmed, blocked, created_at FROM server_users ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id, username, email, createdAt string
		var confirmed, blocked int
		rows.Scan(&id, &username, &email, &confirmed, &blocked, &createdAt)
		users = append(users, map[string]interface{}{
			"id": id, "username": username, "email": email,
			"confirmed": confirmed, "blocked": blocked, "created_at": createdAt,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Users</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0f0;margin:0;padding:2rem}
h1{color:#4ecca3}table{width:100%;border-collapse:collapse}th{text-align:left;padding:0.5rem;border-bottom:1px solid #0f3460;color:#a0a0b8}
td{padding:0.5rem;border-bottom:1px solid #0f3460}a{color:#4ecca3}</style></head><body>
<h1>Users <a href="/admin/dashboard">← Dashboard</a></h1>
<table><tr><th>Username</th><th>Email</th><th>Confirmed</th><th>Blocked</th><th>Created</th></tr>`))

	for _, u := range users {
		confirmed := "✅"
		if u["confirmed"].(int) == 0 {
			confirmed = "❌"
		}
		blocked := ""
		if u["blocked"].(int) != 0 {
			blocked = "🚫"
		}
		w.Write([]byte(`<tr><td>` + u["username"].(string) + `</td><td>` + u["email"].(string) +
			`</td><td>` + confirmed + `</td><td>` + blocked + `</td><td>` + u["created_at"].(string) + `</td></tr>`))
	}
	w.Write([]byte(`</table></body></html>`))
}

func (s *Server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	rows, err := s.db.Query(`SELECT d.id, d.name, d.client_version, COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at
		FROM server_devices d ORDER BY d.created_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Devices</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0f0;margin:0;padding:2rem}
h1{color:#4ecca3}table{width:100%;border-collapse:collapse}th{text-align:left;padding:0.5rem;border-bottom:1px solid #0f3460;color:#a0a0b8}
td{padding:0.5rem;border-bottom:1px solid #0f3460}a{color:#4ecca3}</style></head><body>
<h1>Devices <a href="/admin/dashboard">← Dashboard</a></h1>
<table><tr><th>Name</th><th>ID</th><th>Version</th><th>Last Seen</th><th>Revoked</th><th>Created</th></tr>`))

	for rows.Next() {
		var id, name, clientVer, lastSeen, revokedAt, createdAt string
		rows.Scan(&id, &name, &clientVer, &lastSeen, &revokedAt, &createdAt)
		if lastSeen == "" {
			lastSeen = "never"
		}
		if revokedAt == "" {
			revokedAt = "-"
		}
		w.Write([]byte(`<tr><td>` + name + `</td><td style="font-family:monospace;font-size:0.8em">` + id +
			`</td><td>` + clientVer + `</td><td>` + lastSeen + `</td><td>` + revokedAt + `</td><td>` + createdAt + `</td></tr>`))
	}
	w.Write([]byte(`</table></body></html>`))
}

func (s *Server) requireAdminCookie(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return false
	}
	if !s.tokens.Check(cookie.Value) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return false
	}
	return true
}

func intToStr(n int) string {
	b, _ := json.Marshal(n)
	return strings.Trim(string(b), "\"")
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	var opsCount int
	s.db.QueryRow("SELECT COUNT(*) FROM server_ops").Scan(&opsCount)
	jsonOK(w, map[string]int{"ops": opsCount})
}

func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
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
		jsonOK(w, map[string]interface{}{"ok": false, "error": "host, port and from required"})
		return
	}
	if err := s.smtpTest(host, port, user, pass, security, from, to); err != nil {
		jsonOK(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true})
}

func (s *Server) handleAdminAPIDevices(w http.ResponseWriter, r *http.Request) {
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
		jsonErr(w, 500, err.Error())
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
		rows, err := s.db.Query("SELECT id, name, api_key FROM server_devices ORDER BY created_at")
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var out []map[string]string
		for rows.Next() {
			var id, name, key string
			rows.Scan(&id, &name, &key)
			out = append(out, map[string]string{"id": id, "name": name, "api_key": key})
		}
		jsonOK(w, out)
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleAdminAPISmtp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
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
	if !s.requireAdminCookie(w, r) {
		return
	}
	if r.Method != "DELETE" {
		jsonErr(w, 405, "DELETE required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/keys/")
	_, err := s.db.Exec("DELETE FROM server_devices WHERE id=?", id)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.db.Exec("DELETE FROM server_user_devices WHERE device_id=?", id)
	jsonOK(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleAdminAPIUsers(w http.ResponseWriter, r *http.Request) {
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
		jsonErr(w, 500, err.Error())
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
	if !s.requireAdminCookie(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")

	if strings.HasSuffix(path, "/block") && r.Method == "POST" {
		id := strings.TrimSuffix(path, "/block")
		id = strings.TrimSuffix(id, "/")
		var blocked int
		s.db.QueryRow("SELECT blocked FROM server_users WHERE id=?", id).Scan(&blocked)
		newVal := 1
		if blocked != 0 {
			newVal = 0
		}
		s.db.Exec("UPDATE server_users SET blocked=? WHERE id=?", newVal, id)
		jsonOK(w, map[string]interface{}{"status": "ok", "blocked": newVal})
		return
	}
	if strings.HasSuffix(path, "/reset-password") && r.Method == "POST" {
		id := strings.TrimSuffix(path, "/reset-password")
		id = strings.TrimSuffix(id, "/")
		b := make([]byte, 12)
		rand.Read(b)
		newPass := hex.EncodeToString(b)
		hash, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		_, err := s.db.Exec("UPDATE server_users SET password_hash=? WHERE id=?", string(hash), id)
		if err != nil {
			jsonErr(w, 500, err.Error())
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
		if err := json.NewDecoder(r.Body).Decode(&editReq); err != nil {
			jsonErr(w, 400, "bad json")
			return
		}
		if editReq.Username == "" || editReq.Email == "" {
			jsonErr(w, 400, "username and email required")
			return
		}
		_, err := s.db.Exec("UPDATE server_users SET username=?, email=? WHERE id=?", editReq.Username, strings.ToLower(editReq.Email), id)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"status": "ok"})
		return
	}
	if r.Method == "DELETE" {
		id := strings.TrimSuffix(path, "/")
		rows, _ := s.db.Query("SELECT device_id FROM server_user_devices WHERE user_id=?", id)
		var deviceIDs []string
		for rows.Next() {
			var did string
			rows.Scan(&did)
			deviceIDs = append(deviceIDs, did)
		}
		rows.Close()
		for _, did := range deviceIDs {
			s.db.Exec("DELETE FROM server_devices WHERE id=?", did)
		}
		s.db.Exec("DELETE FROM server_user_devices WHERE user_id=?", id)
		s.db.Exec("DELETE FROM server_email_tokens WHERE user_id=?", id)
		s.db.Exec("DELETE FROM server_users WHERE id=?", id)
		jsonOK(w, map[string]interface{}{"status": "deleted"})
		return
	}
	jsonErr(w, 404, "unknown action")
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	locale := s.locale()
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(adminCreateUserHTML(locale)))
	case "POST":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if username == "" || email == "" || password == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(400)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.allFieldsRequired"), "/admin/create-user")))
			return
		}
		if err := validatePassword(password); err != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(400)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), string(err), "/admin/create-user")))
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(500)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), "internal error", "/admin/create-user")))
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		id := make([]byte, 12)
		rand.Read(id)
		userID := hex.EncodeToString(id)
		_, err = s.db.Exec(
			"INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 1, ?)",
			userID, username, strings.ToLower(email), string(hash), now,
		)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if strings.Contains(err.Error(), "UNIQUE") {
				w.WriteHeader(409)
				w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), "Username or email already taken", "/admin/create-user")))
			} else {
				w.WriteHeader(500)
				w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), err.Error(), "/admin/create-user")))
			}
			return
		}
		http.Redirect(w, r, "/admin/users", http.StatusFound)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleAdminAPICreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminCookie(w, r) {
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
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
			jsonErr(w, 500, err.Error())
		}
		return
	}
	jsonOK(w, map[string]string{"status": "ok", "user_id": userID})
}

var _ = time.Now
var _ = rand.Read
var _ = hex.EncodeToString
