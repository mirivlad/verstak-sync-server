package server

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) requireAdminMutation(w http.ResponseWriter, r *http.Request) bool {
	session, ok := s.requireSession(w, r, sessionScopeAdmin)
	if !ok {
		return false
	}
	return s.verifyCSRF(w, r, session)
}

func (s *Server) requireUserMutation(w http.ResponseWriter, r *http.Request) bool {
	session, ok := s.requireSession(w, r, sessionScopeUser)
	if !ok {
		return false
	}
	return s.verifyCSRF(w, r, session)
}

func (s *Server) verifyCSRF(w http.ResponseWriter, r *http.Request, session webSession) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		jsonErrCode(w, http.StatusForbidden, "csrf_invalid", "CSRF token is required")
		return false
	}
	candidate := r.Header.Get("X-CSRF-Token")
	if candidate == "" {
		// Form parsing is only needed for regular HTML form posts. JSON callers
		// must send the header, avoiding any interference with their decoder.
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseForm(); err != nil {
				jsonErrCode(w, http.StatusBadRequest, "invalid_request", "invalid form")
				return false
			}
			candidate = r.FormValue("csrf_token")
		}
	}
	if candidate == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(candidate)) != 1 || subtle.ConstantTimeCompare([]byte(sha256Hex(candidate)), []byte(session.CSRFHash)) != 1 {
		jsonErrCode(w, http.StatusForbidden, "csrf_invalid", "CSRF token is invalid")
		return false
	}
	if !s.sameOrigin(r) {
		jsonErrCode(w, http.StatusForbidden, "csrf_invalid", "request origin is not allowed")
		return false
	}
	return true
}

func (s *Server) sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Older same-origin form submissions can omit Origin. The CSRF token is
		// still mandatory, so accepting this remains protected.
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		return false
	}
	expected := strings.TrimSpace(s.cfg.PublicURL)
	if expected != "" {
		expectedURL, err := url.Parse(expected)
		return err == nil && strings.EqualFold(originURL.Scheme, expectedURL.Scheme) && strings.EqualFold(originURL.Host, expectedURL.Host)
	}
	scheme := "http"
	if s.requestIsHTTPS(r) {
		scheme = "https"
	}
	return strings.EqualFold(originURL.Scheme, scheme) && strings.EqualFold(originURL.Host, r.Host)
}
