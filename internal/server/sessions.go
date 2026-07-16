package server

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionScopeAdmin = "admin"
	sessionScopeUser  = "user"
	sessionLifetime   = 24 * time.Hour
)

type webSession struct {
	Scope     string
	SubjectID string
	CSRFHash  string
	ExpiresAt time.Time
}

func randomSecret(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createSession stores only hashes. The plaintext session and CSRF values are
// returned once to be placed in cookies or an API login response.
func (s *Server) createSession(scope, subjectID string) (token, csrf string, err error) {
	if scope != sessionScopeAdmin && scope != sessionScopeUser {
		return "", "", fmt.Errorf("unknown session scope")
	}
	token, err = randomSecret(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomSecret(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO server_sessions
		(token_hash, csrf_hash, scope, subject_id, expires_at, created_at, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sha256Hex(token), sha256Hex(csrf), scope, subjectID,
		now.Add(sessionLifetime).Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return "", "", err
	}
	return token, csrf, nil
}

func (s *Server) loadSession(token, scope string) (webSession, bool) {
	if token == "" {
		return webSession{}, false
	}
	var session webSession
	var storedTokenHash string
	var expiresAt string
	err := s.db.QueryRow(`SELECT token_hash, csrf_hash, scope, subject_id, expires_at
		FROM server_sessions WHERE token_hash=? AND scope=?`, sha256Hex(token), scope).
		Scan(&storedTokenHash, &session.CSRFHash, &session.Scope, &session.SubjectID, &expiresAt)
	if err != nil {
		return webSession{}, false
	}
	expires, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !time.Now().UTC().Before(expires) {
		_, _ = s.db.Exec("DELETE FROM server_sessions WHERE token_hash=?", sha256Hex(token))
		return webSession{}, false
	}
	session.ExpiresAt = expires
	// The database lookup is indexed by a fixed-size hash. Keep a constant-time
	// comparison at the final token-hash boundary as well.
	if subtle.ConstantTimeCompare([]byte(storedTokenHash), []byte(sha256Hex(token))) != 1 {
		return webSession{}, false
	}
	_, _ = s.db.Exec("UPDATE server_sessions SET last_seen=? WHERE token_hash=?", time.Now().UTC().Format(time.RFC3339), sha256Hex(token))
	return session, true
}

func (s *Server) deleteSession(token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.Exec("DELETE FROM server_sessions WHERE token_hash=?", sha256Hex(token))
	return err
}

func (s *Server) deleteSessionsForSubject(scope, subjectID string) error {
	_, err := s.db.Exec("DELETE FROM server_sessions WHERE scope=? AND subject_id=?", scope, subjectID)
	return err
}

func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, scope, token, csrf string) {
	name := "user_session"
	path := "/"
	if scope == sessionScopeAdmin {
		name = "admin_session"
		path = "/admin"
	}
	secure := s.requestIsHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: token, Path: path, HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionLifetime.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token", Value: csrf, Path: path, HttpOnly: false, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds()),
	})
}

func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request, scope string) {
	name := "user_session"
	path := "/"
	if scope == sessionScopeAdmin {
		name = "admin_session"
		path = "/admin"
	}
	secure := s.requestIsHTTPS(r)
	for _, cookieName := range []string{name, "csrf_token"} {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: path, HttpOnly: cookieName != "csrf_token", Secure: secure, MaxAge: -1})
	}
}

func (s *Server) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s == nil || s.cfg == nil {
		return false
	}
	if !s.remotePeerIsTrusted(r) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, scope string) (webSession, bool) {
	name := "user_session"
	login := "/login"
	if scope == sessionScopeAdmin {
		name = "admin_session"
		login = "/admin/login"
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		http.Redirect(w, r, login, http.StatusFound)
		return webSession{}, false
	}
	session, ok := s.loadSession(cookie.Value, scope)
	if !ok {
		http.Redirect(w, r, login, http.StatusFound)
		return webSession{}, false
	}
	return session, true
}

func (s *Server) cleanupExpiredSessions() error {
	_, err := s.db.Exec("DELETE FROM server_sessions WHERE expires_at <= ?", time.Now().UTC().Format(time.RFC3339))
	return err
}

func isNoRows(err error) bool {
	return err == sql.ErrNoRows
}
