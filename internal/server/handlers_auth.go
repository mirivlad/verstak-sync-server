package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
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
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.Username == "" || req.Email == "" || req.Password == "" {
		jsonErr(w, 400, "username, email and password required")
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
	_, err = s.db.Exec(
		"INSERT INTO server_users (id, username, email, password_hash, confirmed, created_at) VALUES (?, ?, ?, ?, 0, ?)",
		userID, req.Username, strings.ToLower(req.Email), string(hash), now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonErr(w, 409, "username or email already taken")
			return
		}
		jsonErr(w, 500, err.Error())
		return
	}
	tok := make([]byte, 24)
	rand.Read(tok)
	tokenStr := hex.EncodeToString(tok)
	exp := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	s.db.Exec("INSERT INTO server_email_tokens (token, user_id, purpose, expires_at, created_at) VALUES (?, ?, 'confirm', ?, ?)",
		tokenStr, userID, exp, now)
	log.Printf("register: confirmation token=%s for user %s", tokenStr, req.Username)
	jsonOK(w, map[string]string{"status": "confirmation_sent"})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		jsonErr(w, 400, "token required")
		return
	}
	var userID, expiresAt string
	err := s.db.QueryRow("SELECT user_id, expires_at FROM server_email_tokens WHERE token=? AND purpose='confirm'",
		tokenStr).Scan(&userID, &expiresAt)
	if err != nil {
		jsonErr(w, 400, "invalid or expired token")
		return
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(exp) {
		jsonErr(w, 400, "token expired")
		return
	}
	s.db.Exec("UPDATE server_users SET confirmed=1 WHERE id=?", userID)
	log.Printf("confirm: user %s confirmed email", userID)
	s.db.Exec("DELETE FROM server_email_tokens WHERE token=?", tokenStr)
	jsonOK(w, map[string]string{"status": "confirmed"})
}

func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "username and password required")
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
	s.db.Exec("UPDATE server_users SET last_seen=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), userID)
	tok := s.userTokens.Create(userID)
	jsonOK(w, map[string]string{"token": tok, "user_id": userID})
}

func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.Email == "" {
		jsonErr(w, 400, "email required")
		return
	}
	var userID string
	err := s.db.QueryRow("SELECT id FROM server_users WHERE email=?", strings.ToLower(req.Email)).Scan(&userID)
	if err != nil {
		jsonOK(w, map[string]string{"status": "if email exists, reset link sent"})
		return
	}
	tok := make([]byte, 24)
	rand.Read(tok)
	tokenStr := hex.EncodeToString(tok)
	exp := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	now := time.Now().UTC().Format(time.RFC3339)
	s.db.Exec("INSERT INTO server_email_tokens (token, user_id, purpose, expires_at, created_at) VALUES (?, ?, 'reset', ?, ?)",
		tokenStr, userID, exp, now)
	log.Printf("forgot: reset token=%s for user %s", tokenStr, userID)
	jsonOK(w, map[string]string{"status": "if email exists, reset link sent"})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		jsonErr(w, 400, "token and new_password required")
		return
	}
	if err := validatePassword(req.NewPassword); err != "" {
		jsonErr(w, 400, err)
		return
	}
	var userID, expiresAt string
	err := s.db.QueryRow("SELECT user_id, expires_at FROM server_email_tokens WHERE token=? AND purpose='reset'",
		req.Token).Scan(&userID, &expiresAt)
	if err != nil {
		jsonErr(w, 400, "invalid or expired token")
		return
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(exp) {
		jsonErr(w, 400, "token expired")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, 500, "internal error")
		return
	}
	s.db.Exec("UPDATE server_users SET password_hash=? WHERE id=?", string(hash), userID)
	s.db.Exec("DELETE FROM server_email_tokens WHERE token=?", req.Token)
	jsonOK(w, map[string]string{"status": "password reset"})
}
