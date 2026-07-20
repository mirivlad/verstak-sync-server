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
	session, ok := s.requireSession(w, r, sessionScopeUser)
	if !ok {
		return "", false
	}
	return session.SubjectID, true
}

func (s *Server) renderWebError(w http.ResponseWriter, r *http.Request, status int, message, back string) {
	s.renderPageStatus(w, r, "error", webPage{Title: "error.label", Heading: "error.badRequest", Message: message, BackURL: back}, status)
}

func (s *Server) handleUserWebRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Web.AllowRegistration {
		s.renderWebError(w, r, http.StatusNotFound, "error.registrationDisabled", "/login")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "register", webPage{Title: "auth.registerTitle"})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/register")
			return
		}
		if !s.requirePublicWebMutation(w, r, "/register") {
			return
		}
		username, email, password := strings.TrimSpace(r.FormValue("username")), strings.TrimSpace(r.FormValue("email")), r.FormValue("password")
		if username == "" || email == "" || password == "" {
			s.renderPage(w, r, "register", webPage{Title: "auth.registerTitle", Flash: "error.allFieldsRequired"})
			return
		}
		normalizedEmail, ok := normalizeEmailAddress(email)
		if !ok {
			s.renderPage(w, r, "register", webPage{Title: "auth.registerTitle", Flash: "error.invalidEmail"})
			return
		}
		email = normalizedEmail
		if !s.allowWebRate(w, r, "register", email, "/register") {
			return
		}
		if err := validatePassword(password); err != "" {
			s.renderPage(w, r, "register", webPage{Title: "auth.registerTitle", Flash: "error.passwordInvalid"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("web register: password hashing: %v", err)
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/register")
			return
		}
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/register")
			return
		}
		userID := hex.EncodeToString(id)
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := s.db.Exec("INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 0, ?)", userID, username, email, string(hash), now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderPage(w, r, "register", webPage{Title: "auth.registerTitle", Flash: "error.accountTaken"})
				return
			}
			log.Printf("web register: create user: %v", err)
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/register")
			return
		}
		token, err := issueEmailToken(s.db, userID, "confirm", 48*time.Hour)
		if err != nil {
			log.Printf("web register: issue confirmation token: %v", err)
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/register")
			return
		}
		if host := s.smtpGet("smtp_host"); host != "" {
			base := s.smtpGet("server_url")
			if base == "" {
				base = "http://" + r.Host
			}
			confirmURL := fmt.Sprintf("%s/api/v1/auth/confirm?token=%s", strings.TrimRight(base, "/"), token)
			if err := s.smtpSend(email, t(s.webLocale(r), "server.emailConfirmSubject"), fmt.Sprintf(t(s.webLocale(r), "server.emailConfirmBody"), confirmURL)); err != nil {
				log.Printf("web register: confirmation mail: %v", err)
			}
		} else if s.cfg.DevelopmentTokenLogging {
			log.Printf("development confirmation token for user %s: %s", username, token)
		}
		http.Redirect(w, r, "/register/result", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleUserWebForgot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "forgot", webPage{Title: "auth.forgotTitle"})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/forgot")
			return
		}
		if !s.requirePublicWebMutation(w, r, "/forgot") {
			return
		}
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if email == "" {
			s.renderPage(w, r, "forgot", webPage{Title: "auth.forgotTitle", Flash: "error.emailRequired"})
			return
		}
		if !s.allowWebRate(w, r, "forgot", email, "/forgot") {
			return
		}
		var userID string
		if err := s.db.QueryRow("SELECT id FROM server_users WHERE email=?", email).Scan(&userID); err == nil {
			token, issueErr := issueEmailToken(s.db, userID, "reset", time.Hour)
			if issueErr != nil {
				log.Printf("web forgot: issue reset token: %v", issueErr)
				s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/forgot")
				return
			}
			if s.smtpGet("smtp_host") != "" {
				base := s.smtpGet("server_url")
				if base == "" {
					base = "http://" + r.Host
				}
				resetURL := fmt.Sprintf("%s/reset?token=%s", strings.TrimRight(base, "/"), token)
				if err := s.smtpSend(email, t(s.webLocale(r), "server.emailResetSubject"), fmt.Sprintf(t(s.webLocale(r), "server.emailResetBody"), resetURL)); err != nil {
					log.Printf("web forgot: reset mail: %v", err)
				}
			} else if s.cfg.DevelopmentTokenLogging {
				log.Printf("development reset token requested for %s: %s", email, token)
			}
		}
		http.Redirect(w, r, "/forgot/sent", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) validResetToken(token string) bool {
	var expiresAt string
	if err := s.db.QueryRow("SELECT expires_at FROM server_email_tokens WHERE token_hash=? AND purpose='reset'", emailTokenHash(token)).Scan(&expiresAt); err != nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339, expiresAt)
	return err == nil && time.Now().Before(expires)
}

func (s *Server) handleUserWebReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		if token == "" || !s.validResetToken(token) {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		s.renderPage(w, r, "reset", webPage{Title: "auth.resetTitle", Token: token})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/forgot")
			return
		}
		if !s.requirePublicWebMutation(w, r, "/forgot") {
			return
		}
		token, password, confirm := r.FormValue("token"), r.FormValue("password"), r.FormValue("confirm")
		if token == "" || password == "" || confirm == "" {
			s.renderPage(w, r, "reset", webPage{Title: "auth.resetTitle", Token: token, Flash: "error.allFieldsRequired"})
			return
		}
		if !s.allowWebRate(w, r, "reset", "", "/forgot") {
			return
		}
		if err := validatePassword(password); err != "" {
			s.renderPage(w, r, "reset", webPage{Title: "auth.resetTitle", Token: token, Flash: "error.passwordInvalid"})
			return
		}
		if password != confirm {
			s.renderPage(w, r, "reset", webPage{Title: "auth.resetTitle", Token: token, Flash: "error.passwordMismatch"})
			return
		}
		userID, err := s.resetPasswordWithToken(token, password)
		if err == errResetTokenInvalid || err == errResetTokenExpired {
			http.Redirect(w, r, "/forgot", http.StatusFound)
			return
		}
		if err != nil {
			log.Printf("web reset: %v", err)
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/forgot")
			return
		}
		log.Printf("reset: user %s reset password", userID)
		http.Redirect(w, r, "/reset/done", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleUserWebLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "login", webPage{Title: "auth.loginTitle"})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/login")
			return
		}
		if !s.requirePublicWebMutation(w, r, "/login") {
			return
		}
		login, password := strings.TrimSpace(r.FormValue("username")), r.FormValue("password")
		if !s.allowWebRate(w, r, "login", login, "/login") {
			return
		}
		var userID, hash string
		var confirmed, blocked int
		err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?", login, strings.ToLower(login)).Scan(&userID, &hash, &confirmed, &blocked)
		if err != nil || blocked != 0 || confirmed == 0 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			s.renderPageStatus(w, r, "login", webPage{Title: "auth.loginTitle", Flash: "error.invalidCredentials"}, http.StatusUnauthorized)
			return
		}
		token, csrf, err := s.createSession(sessionScopeUser, userID)
		if err != nil {
			log.Printf("web login: session: %v", err)
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/login")
			return
		}
		s.setSessionCookies(w, r, sessionScopeUser, token, csrf)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleUserDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	userID, ok := s.requireUserWeb(w, r)
	if !ok {
		return
	}
	var username, email string
	var confirmed int
	if err := s.db.QueryRow("SELECT username, email, confirmed FROM server_users WHERE id=?", userID).Scan(&username, &email, &confirmed); err != nil {
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	where := " WHERE ud.user_id=?"
	args := []interface{}{userID}
	if query != "" {
		like := "%" + query + "%"
		where += " AND (d.name LIKE ? OR d.vault_id LIKE ? OR d.client_version LIKE ?)"
		args = append(args, like, like, like)
	}
	rows, err := s.db.Query(`SELECT d.id, d.name, COALESCE(d.vault_id,''), COALESCE(d.client_version,''), COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at FROM server_devices d JOIN server_user_devices ud ON ud.device_id=d.id`+where+` ORDER BY d.created_at DESC`, args...)
	if err != nil {
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/")
		return
	}
	defer rows.Close()
	var devices []webDevice
	for rows.Next() {
		var d webDevice
		var revoked string
		if err := rows.Scan(&d.ID, &d.Name, &d.Vault, &d.ClientVersion, &d.LastSeen, &revoked, &d.CreatedAt); err != nil {
			s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/")
			return
		}
		d.Revoked = revoked != ""
		if d.LastSeen == "" {
			d.LastSeen = "—"
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		s.renderWebError(w, r, http.StatusInternalServerError, "error.internal", "/")
		return
	}
	flash := r.URL.Query().Get("flash")
	flashError := false
	if flash == "" {
		flash = r.URL.Query().Get("error")
		flashError = flash != ""
	}
	if flash != "error.invalidCredentials" && flash != "user.deviceRevoked" {
		flash = ""
	}
	s.renderPage(w, r, "dashboard", webPage{Title: "user.account", UserName: username, Email: email, UserConfirmed: confirmed != 0, Devices: devices, Flash: flash, FlashError: flashError, List: webList{Query: query}})
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
	rows, err := s.db.Query(`SELECT d.id,d.name,COALESCE(d.client_version,''),COALESCE(d.last_seen,''),COALESCE(d.revoked_at,''),d.created_at FROM server_devices d JOIN server_user_devices ud ON ud.device_id=d.id WHERE ud.user_id=? ORDER BY d.created_at DESC`, userID)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer rows.Close()
	var devices []map[string]string
	for rows.Next() {
		var id, name, version, lastSeen, revoked, created string
		if err := rows.Scan(&id, &name, &version, &lastSeen, &revoked, &created); err != nil {
			jsonInternalError(w, err)
			return
		}
		devices = append(devices, map[string]string{"id": id, "name": name, "client_version": version, "last_seen": lastSeen, "revoked_at": revoked, "created_at": created})
	}
	if err := rows.Err(); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, devices)
}

// handleUserWebDeviceAction accepts the dashboard's regular form as well as
// the existing JSON API. Both paths are session and CSRF protected.
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
	password := ""
	formRequest := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if formRequest {
		password = r.FormValue("password")
	} else {
		var req struct {
			Password string `json:"password"`
		}
		if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
			return
		}
		password = req.Password
	}
	if password == "" {
		if formRequest {
			http.Redirect(w, r, "/dashboard?error=error.invalidCredentials", http.StatusSeeOther)
		} else {
			jsonErrCode(w, http.StatusBadRequest, "invalid_request", "password required")
		}
		return
	}
	if formRequest {
		if !s.allowWebRate(w, r, "auth-test", session.SubjectID, "/dashboard") {
			return
		}
	} else if !s.allowRate(w, r, "auth-test", session.SubjectID) {
		return
	}
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM server_users WHERE id=?", session.SubjectID).Scan(&hash); err != nil {
		jsonInternalError(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		if formRequest {
			http.Redirect(w, r, "/dashboard?error=error.invalidCredentials", http.StatusSeeOther)
		} else {
			jsonErr(w, http.StatusForbidden, "wrong password")
		}
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
	if formRequest {
		http.Redirect(w, r, "/dashboard?flash=user.deviceRevoked", http.StatusSeeOther)
		return
	}
	jsonOK(w, map[string]string{"status": "revoked"})
}
