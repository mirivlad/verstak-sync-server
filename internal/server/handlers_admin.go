package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
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

var _ = time.Now
var _ = rand.Read
var _ = hex.EncodeToString
