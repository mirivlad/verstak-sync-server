package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) requireUserWeb(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie("user_session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return "", false
	}
	userID, ok := s.userTokens.Check(cookie.Value)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return "", false
	}
	return userID, true
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
				w.WriteHeader(500)
				w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), err.Error(), "/register")))
			}
			return
		}
		tok := make([]byte, 24)
		rand.Read(tok)
		tokenStr := hex.EncodeToString(tok)
		exp := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
		s.db.Exec("INSERT INTO server_email_tokens (token, user_id, purpose, expires_at, created_at) VALUES (?, ?, 'confirm', ?, ?)",
			tokenStr, userID, exp, now)
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
		} else {
			log.Printf("register web: SMTP not configured, confirmation token=%s for user %s", tokenStr, username)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		regMsg := registrationOKHTML(locale)
		if host == "" {
			regMsg = registrationAutoHTML(locale)
		}
		w.Write([]byte(regMsg))
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
		var userID string
		err := s.db.QueryRow("SELECT id FROM server_users WHERE email=?", email).Scan(&userID)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(forgotSentHTML(locale)))
			return
		}
		tok := make([]byte, 24)
		rand.Read(tok)
		tokenStr := hex.EncodeToString(tok)
		exp := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
		now := time.Now().UTC().Format(time.RFC3339)
		s.db.Exec("INSERT INTO server_email_tokens (token, user_id, purpose, expires_at, created_at) VALUES (?, ?, 'reset', ?, ?)",
			tokenStr, userID, exp, now)
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
		} else {
			log.Printf("forgot web: SMTP not configured, reset token=%s for email %s", tokenStr, email)
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
		err := s.db.QueryRow("SELECT user_id, expires_at FROM server_email_tokens WHERE token=? AND purpose='reset'",
			token).Scan(&userID, &expiresAt)
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
		html := strings.ReplaceAll(resetPasswordHTML(locale), "{TOKEN}", token)
		w.Write([]byte(html))
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
		if err := validatePassword(newPass); err != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), string(err), "/reset?token="+token)))
			return
		}
		if newPass != confirm {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(errorPageHTML(locale, t(locale, "common.error"), t(locale, "server.passwordsDoNotMatch"), "/reset?token="+token)))
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
		tok := s.userTokens.Create(userID)
		http.SetCookie(w, &http.Cookie{
			Name: "user_session", Value: tok, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
			MaxAge: 86400,
		})
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
			revokeBtn := fmt.Sprintf(`<button class="btn btn-danger btn-sm" onclick="revokeDevice('%s')">%s</button>`, d.ID, t(locale, "userDashboard.revoke"))
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
			</tr>`, d.Name, status, created, ls, d.ClientVer, revokeBtn)
		}
	}

	w.Write([]byte(userDashboardHTML(locale, username, deviceRows)))
}

func (s *Server) handleUserWebLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "user_session", Value: "", Path: "/",
		HttpOnly: true, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleUserDevices(w http.ResponseWriter, r *http.Request) {
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
	}
	var devices []devDTO
	for rows.Next() {
		var d devDTO
		rows.Scan(&d.ID, &d.Name, &d.ClientVersion, &d.LastSeen, &d.RevokedAt, &d.CreatedAt)
		devices = append(devices, d)
	}
	jsonOK(w, devices)
}
