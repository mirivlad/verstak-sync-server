package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) requireUserWeb(w http.ResponseWriter, r *http.Request) (string, bool) {
	session, ok := s.requireSession(w, r, sessionScopeUser)
	if !ok {
		return "", false
	}
	return session.SubjectID, true
}

func (s *Server) handleUserWebRegister(w http.ResponseWriter, r *http.Request) {
	locale := s.locale()
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(userRegisterHTML(locale)))
	case "POST":
		if err := r.ParseForm(); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(400)
			w.Write([]byte(errorPageHTML(locale, "400 Bad request", "400 Bad request", "/register")))
			return
		}
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if username == "" || email == "" || password == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(400)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.allFieldsRequired"), "/register")))
			return
		}
		if !s.allowRate(w, r, "register", email) {
			return
		}
		if err := validatePassword(password); err != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(400)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), string(err), "/register")))
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(500)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), "internal error", "/register")))
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		id := make([]byte, 12)
		rand.Read(id)
		userID := hex.EncodeToString(id)
		_, err = s.db.Exec(
			"INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 0, ?)",
			userID, username, strings.ToLower(email), string(hash), now,
		)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if strings.Contains(err.Error(), "UNIQUE") {
				w.WriteHeader(409)
				w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), "Username or email already taken", "/register")))
			} else {
				log.Printf("register web: create user failed: %v", err)
				w.WriteHeader(500)
				w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.registrationFailed"), "/register")))
			}
			return
		}
		tokenStr, err := issueEmailToken(s.db, userID, "confirm", 48*time.Hour)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		host := s.smtpGet("smtp_host")
		if host != "" {
			srvURL := s.smtpGet("server_url")
			var confirmURL string
			if srvURL != "" {
				confirmURL = fmt.Sprintf("%s/api/v1/auth/confirm?token=%s", srvURL, tokenStr)
			} else {
				confirmURL = fmt.Sprintf("http://%s/api/v1/auth/confirm?token=%s", r.Host, tokenStr)
			}
			body := fmt.Sprintf(t(locale, "server.emailConfirmBody"), confirmURL)
			if err := s.smtpSend(email, t(locale, "server.emailConfirmSubject"), body); err != nil {
				log.Printf("register web: failed to send confirm email: %v", err)
			}
		} else if s.cfg.DevelopmentTokenLogging {
			log.Printf("development confirmation token for user %s: %s", username, tokenStr)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(registrationOKHTML(locale)))
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleUserWebForgot(w http.ResponseWriter, r *http.Request) {
	locale := s.locale()
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(forgotPasswordHTML(locale)))
	case "POST":
		if err := r.ParseForm(); err != nil {
			jsonErr(w, 400, "bad form")
			return
		}
		email := strings.ToLower(r.FormValue("email"))
		if email == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.needEmail"), "/forgot")))
			return
		}
		if !s.allowRate(w, r, "forgot", email) {
			return
		}
		var userID string
		err := s.db.QueryRow("SELECT id FROM server_users WHERE email=?", email).Scan(&userID)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(forgotSentHTML(locale)))
			return
		}
		tokenStr, err := issueEmailToken(s.db, userID, "reset", time.Hour)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		host := s.smtpGet("smtp_host")
		if host != "" {
			srvURL := s.smtpGet("server_url")
			resetURL := fmt.Sprintf("/reset?token=%s", tokenStr)
			if srvURL != "" {
				resetURL = fmt.Sprintf("%s/reset?token=%s", srvURL, tokenStr)
			}
			body := fmt.Sprintf(t(locale, "server.emailResetBody"), resetURL)
			if err := s.smtpSend(email, t(locale, "server.emailResetSubject"), body); err != nil {
				log.Printf("forgot web: failed to send reset email: %v", err)
			}
		} else if s.cfg.DevelopmentTokenLogging {
			log.Printf("development reset token requested for %s: %s", email, tokenStr)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(forgotSentHTML(locale)))
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleUserWebReset(w http.ResponseWriter, r *http.Request) {
	locale := s.locale()
	switch r.Method {
	case "GET":
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		var userID, expiresAt string
		err := s.db.QueryRow("SELECT user_id, expires_at FROM server_email_tokens WHERE token_hash=? AND purpose='reset'",
			emailTokenHash(token)).Scan(&userID, &expiresAt)
		if err != nil {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		exp, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil || time.Now().After(exp) {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := strings.ReplaceAll(resetPasswordHTML(locale), "{TOKEN}", html.EscapeString(token))
		w.Write([]byte(page))
	case "POST":
		if err := r.ParseForm(); err != nil {
			jsonErr(w, 400, "bad form")
			return
		}
		token := r.FormValue("token")
		newPass := r.FormValue("password")
		confirm := r.FormValue("confirm")
		if token == "" || newPass == "" || confirm == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.allFieldsRequired"), "/forgot")))
			return
		}
		if !s.allowRate(w, r, "reset", "") {
			return
		}
		if err := validatePassword(newPass); err != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), string(err), "/reset?token="+url.QueryEscape(token))))
			return
		}
		if newPass != confirm {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.passwordsDoNotMatch"), "/reset?token="+url.QueryEscape(token))))
			return
		}
		userID, err := s.resetPasswordWithToken(token, newPass)
		if err == errResetTokenInvalid || err == errResetTokenExpired {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "common.error"), "/forgot")))
			return
		}
		log.Printf("reset: user %s reset password", userID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(resetDoneHTML(locale)))
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleUserWebLogin(w http.ResponseWriter, r *http.Request) {
	locale := s.locale()
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(userLoginHTML(locale)))
	case "POST":
		if err := r.ParseForm(); err != nil {
			jsonErr(w, 400, "bad form")
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		if !s.allowRate(w, r, "login", username) {
			return
		}
		var userID, hash string
		var confirmed, blocked int
		err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
			username, strings.ToLower(username)).Scan(&userID, &hash, &confirmed, &blocked)
		if err != nil || blocked != 0 || confirmed == 0 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(401)
			w.Write([]byte(errorPageHTML(locale, "401 Unauthorized", "401 Unauthorized", "/login")))
			return
		}
		tok, csrf, err := s.createSession(sessionScopeUser, userID)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		s.setSessionCookies(w, r, sessionScopeUser, tok, csrf)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleUserDashboard(w http.ResponseWriter, r *http.Request) {
	locale := s.locale()
	userID, ok := s.requireUserWeb(w, r)
	if !ok {
		return
	}
	var username string
	s.db.QueryRow("SELECT username FROM server_users WHERE id=?", userID).Scan(&username)

	type dev struct {
		ID, Name, LastSeen, CreatedAt, ClientVer, RevokedAt string
	}
	var devices []dev
	rows, err := s.db.Query(`
		SELECT d.id, d.name, COALESCE(d.last_seen,''), d.created_at,
		       COALESCE(d.client_version,''), COALESCE(d.revoked_at,'')
		FROM server_devices d
		JOIN server_user_devices ud ON ud.device_id = d.id
		WHERE ud.user_id = ?
		ORDER BY d.created_at DESC`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d dev
			rows.Scan(&d.ID, &d.Name, &d.LastSeen, &d.CreatedAt, &d.ClientVer, &d.RevokedAt)
			devices = append(devices, d)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	deviceRows := ""
	if len(devices) == 0 {
		deviceRows = "<tr><td colspan='5' style='color:#666;text-align:center;padding:24px'>" + t(locale, "userDashboard.noDevices") + "</td></tr>"
	} else {
		for _, d := range devices {
			ls := d.LastSeen
			if ls == "" {
				ls = "—"
			}
			created := d.CreatedAt
			if len(created) > 10 {
				created = created[:10]
			}
			status := "<span style='color:#34d399'>" + t(locale, "userDashboard.active") + "</span>"
			revokeBtn := fmt.Sprintf(`<button class="btn btn-danger btn-sm" onclick="revokeDevice(%s)">%s</button>`, html.EscapeString(strconv.Quote(d.ID)), t(locale, "userDashboard.revoke"))
			if d.RevokedAt != "" {
				status = "<span style='color:#ff6b6b'>" + t(locale, "userDashboard.revoked") + "</span>"
				revokeBtn = ""
			}
			deviceRows += fmt.Sprintf(`<tr>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s %s</td>
			</tr>`, html.EscapeString(d.Name), status, html.EscapeString(created), html.EscapeString(ls), html.EscapeString(d.ClientVer), revokeBtn)
		}
	}

	csrf := ""
	if cookie, err := r.Cookie("csrf_token"); err == nil {
		csrf = cookie.Value
	}
	w.Write([]byte(userDashboardHTML(locale, html.EscapeString(username), deviceRows, csrf)))
}

func (s *Server) handleUserWebLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.requireUserMutation(w, r) {
		return
	}
	if cookie, err := r.Cookie("user_session"); err == nil {
		if err := s.deleteSession(cookie.Value); err != nil {
			jsonInternalError(w, err)
			return
		}
	}
	s.clearSessionCookies(w, r, sessionScopeUser)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleUserDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	userID, ok := s.requireUserWeb(w, r)
	if !ok {
		return
	}

	rows, err := s.db.Query(`
		SELECT d.id, d.name, COALESCE(d.client_version,''), COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at
		FROM server_devices d
		JOIN server_user_devices ud ON ud.device_id = d.id
		WHERE ud.user_id = ?
		ORDER BY d.created_at DESC`, userID)
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
	}
	var devices []devDTO
	for rows.Next() {
		var d devDTO
		rows.Scan(&d.ID, &d.Name, &d.ClientVersion, &d.LastSeen, &d.RevokedAt, &d.CreatedAt)
		devices = append(devices, d)
	}
	jsonOK(w, devices)
}

// handleUserWebDeviceAction is deliberately session/CSRF based. Browser UI
// never receives a desktop device bearer token.
func (s *Server) handleUserWebDeviceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	session, ok := s.requireSession(w, r, sessionScopeUser)
	if !ok || !s.verifyCSRF(w, r, session) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/user/devices/")
	if !strings.HasSuffix(path, "/revoke") {
		jsonErr(w, http.StatusNotFound, "not found")
		return
	}
	deviceID := strings.TrimSuffix(strings.TrimSuffix(path, "/revoke"), "/")
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Password == "" || !s.allowRate(w, r, "auth-test", session.SubjectID) {
		if req.Password == "" {
			jsonErrCode(w, http.StatusBadRequest, "invalid_request", "password required")
		}
		return
	}
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM server_users WHERE id=?", session.SubjectID).Scan(&hash); err != nil {
		jsonInternalError(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		jsonErr(w, http.StatusForbidden, "wrong password")
		return
	}
	var owner string
	if err := s.db.QueryRow("SELECT user_id FROM server_devices WHERE id=?", deviceID).Scan(&owner); err != nil {
		jsonErr(w, http.StatusNotFound, "device not found")
		return
	}
	if owner != session.SubjectID {
		jsonErr(w, http.StatusForbidden, "device does not belong to you")
		return
	}
	if err := s.revokeDevice(deviceID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		jsonInternalError(w, err)
		return
	}
	s.auditLog("device_revoked", session.SubjectID, deviceID, s.clientIP(r), "device revoked from web dashboard")
	jsonOK(w, map[string]string{"status": "revoked"})
}
