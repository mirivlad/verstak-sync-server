package server

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Username == "" || req.Email == "" || req.Password == "" {
		jsonErr(w, 400, "username, email and password required")
		return
	}
	if !s.allowRate(w, r, "register", req.Email) {
		return
	}
	if err := validatePassword(req.Password); err != "" {
		jsonErr(w, 400, err)
		return
	}
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		jsonErr(w, 400, "invalid email")
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
	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(
		"INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 0, ?)",
		userID, req.Username, strings.ToLower(req.Email), string(hash), now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonErr(w, 409, "username or email already taken")
			return
		}
		jsonInternalError(w, err)
		return
	}
	if _, err := issueEmailToken(tx, userID, "confirm", 48*time.Hour); err != nil {
		jsonInternalError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]string{"status": "confirmation_sent"})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/login")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		s.renderPage(w, r, "confirm", webPage{Title: "confirm.title", Token: tokenStr})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	tokenStr := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			Token string `json:"token"`
		}
		if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
			return
		}
		tokenStr = req.Token
	} else if err := r.ParseForm(); err == nil {
		tokenStr = r.FormValue("token")
	} else {
		jsonErrCode(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	if tokenStr == "" {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 400, "token required")
		} else {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/login")
		}
		return
	}
	var userID, expiresAt string
	err := s.db.QueryRow("SELECT user_id, expires_at FROM server_email_tokens WHERE token_hash=? AND purpose='confirm'",
		emailTokenHash(tokenStr)).Scan(&userID, &expiresAt)
	if err != nil {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 400, "invalid or expired token")
		} else {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/login")
		}
		return
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(exp) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 400, "token expired")
		} else {
			s.renderWebError(w, r, http.StatusBadRequest, "error.tryAgain", "/login")
		}
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE server_users SET confirmed=1 WHERE id=?", userID); err != nil {
		jsonInternalError(w, err)
		return
	}
	if _, err := tx.Exec("DELETE FROM server_email_tokens WHERE token_hash=?", emailTokenHash(tokenStr)); err != nil {
		jsonInternalError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
	log.Printf("confirm: user %s confirmed email", userID)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		jsonOK(w, map[string]string{"status": "confirmed"})
	} else {
		http.Redirect(w, r, "/confirm/result", http.StatusSeeOther)
	}
}

func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "username and password required")
		return
	}
	if !s.allowRate(w, r, "login", req.Username) {
		return
	}
	var userID, hash string
	var confirmed, blocked int
	err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
		req.Username, strings.ToLower(req.Username)).Scan(&userID, &hash, &confirmed, &blocked)
	if err != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if blocked != 0 {
		jsonErr(w, 403, "account blocked")
		return
	}
	if confirmed == 0 {
		jsonErr(w, 403, "email not confirmed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if _, err := s.db.Exec("UPDATE server_users SET last_seen=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), userID); err != nil {
		jsonInternalError(w, err)
		return
	}
	tok, _, err := s.createSession(sessionScopeUser, userID)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]string{"token": tok, "user_id": userID})
}

func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Email == "" {
		jsonErr(w, 400, "email required")
		return
	}
	if !s.allowRate(w, r, "forgot", req.Email) {
		return
	}
	var userID string
	err := s.db.QueryRow("SELECT id FROM server_users WHERE email=?", strings.ToLower(req.Email)).Scan(&userID)
	if err != nil {
		jsonOK(w, map[string]string{"status": "if email exists, reset link sent"})
		return
	}
	if _, err := issueEmailToken(s.db, userID, "reset", time.Hour); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]string{"status": "if email exists, reset link sent"})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		jsonErr(w, 400, "token and new_password required")
		return
	}
	if !s.allowRate(w, r, "reset", "") {
		return
	}
	if err := validatePassword(req.NewPassword); err != "" {
		jsonErr(w, 400, err)
		return
	}
	_, err := s.resetPasswordWithToken(req.Token, req.NewPassword)
	if err == errResetTokenInvalid {
		jsonErr(w, 400, "invalid or expired token")
		return
	}
	if err == errResetTokenExpired {
		jsonErr(w, 400, "token expired")
		return
	}
	if err != nil {
		jsonErr(w, 500, "internal error")
		return
	}
	jsonOK(w, map[string]string{"status": "password reset"})
}
