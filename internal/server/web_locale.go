package server

import (
	"net/http"
	"strings"
)

const webLocaleCookieName = "verstak_locale"

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
