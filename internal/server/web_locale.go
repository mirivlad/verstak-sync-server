package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	webLocaleCookieName     = "verstak_locale"
	webLocaleCSRFCookieName = "verstak_locale_csrf"
)

func isSupportedWebLocale(locale string) bool {
	return locale == "en" || locale == "ru"
}

// resolveWebLocale has a deliberately small, documented locale model. The
// cookie is a user preference; "system" delegates to Accept-Language, then
// the configured server default, and finally English.
func resolveWebLocale(r *http.Request, cfg *Config) string {
	configured := "en"
	if cfg != nil && isSupportedWebLocale(cfg.Web.DefaultLocale) {
		configured = cfg.Web.DefaultLocale
	}
	if cookie, err := r.Cookie(webLocaleCookieName); err == nil {
		switch cookie.Value {
		case "ru", "en":
			return cookie.Value
		case "system":
			if locale := localeFromAcceptLanguage(r.Header.Get("Accept-Language")); locale != "" {
				return locale
			}
			return configured
		default:
			return configured
		}
	}
	if locale := localeFromAcceptLanguage(r.Header.Get("Accept-Language")); locale != "" {
		return locale
	}
	return configured
}

func localeFromAcceptLanguage(header string) string {
	for _, part := range strings.Split(header, ",") {
		language := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if language == "ru" || strings.HasPrefix(language, "ru-") {
			return "ru"
		}
		if language == "en" || strings.HasPrefix(language, "en-") {
			return "en"
		}
	}
	return ""
}

func (s *Server) webLocale(r *http.Request) string {
	return resolveWebLocale(r, s.cfg)
}

func (s *Server) webLocalePreference(r *http.Request) string {
	if cookie, err := r.Cookie(webLocaleCookieName); err == nil && (cookie.Value == "ru" || cookie.Value == "en" || cookie.Value == "system") {
		return cookie.Value
	}
	return "system"
}

func (s *Server) setWebLocale(w http.ResponseWriter, r *http.Request, locale string) {
	secure := s.requestIsHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name: webLocaleCookieName, Value: locale, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 365 * 24 * 60 * 60,
	})
}

// webLocaleCSRF protects the public language-preference form without
// conflating it with session CSRF tokens. Its value is rendered by the server,
// while the matching cookie is HttpOnly and never read by client-side code.
func (s *Server) webLocaleCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(webLocaleCSRFCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	token, err := randomSecret(32)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: webLocaleCSRFCookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: s.requestIsHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: 24 * 60 * 60,
	})
	return token
}

func (s *Server) verifyWebLocaleCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(webLocaleCSRFCookieName)
	if err != nil || cookie.Value == "" || !s.sameOrigin(r) {
		return false
	}
	candidate := r.FormValue("locale_csrf")
	return candidate != "" && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(candidate)) == 1
}

func (s *Server) requirePublicWebMutation(w http.ResponseWriter, r *http.Request, back string) bool {
	if s.verifyWebLocaleCSRF(r) {
		return true
	}
	s.renderWebError(w, r, http.StatusForbidden, "error.tryAgain", back)
	return false
}
