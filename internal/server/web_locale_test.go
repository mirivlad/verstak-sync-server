package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveWebLocaleCookieOverridesSystemAcceptLanguage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Web.DefaultLocale = "en"
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
	req.AddCookie(&http.Cookie{Name: webLocaleCookieName, Value: "en"})

	if got := resolveWebLocale(req, cfg); got != "en" {
		t.Fatalf("locale = %q, want cookie locale en", got)
	}
}

func TestTranslationCatalogsHaveMatchingKeysAndHideUnknownKeys(test *testing.T) {
	for key := range _translations["en"] {
		if _, ok := _translations["ru"][key]; !ok {
			test.Fatalf("English key %q is missing in Russian catalog", key)
		}
	}
	for key := range _translations["ru"] {
		if _, ok := _translations["en"][key]; !ok {
			test.Fatalf("Russian key %q is missing in English catalog", key)
		}
	}
	if got := t("en", "missing.key"); got == "missing.key" || strings.Contains(got, "missing.key") {
		test.Fatalf("unknown key leaked to UI: %q", got)
	}
}

func TestEmbeddedTemplatesUseExternalAssetsAndNoInlineEventHandlers(t *testing.T) {
	entries, err := fs.Glob(webFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range entries {
		body, err := webFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, forbidden := range []string{"<style", " onclick=", " onchange="} {
			if strings.Contains(strings.ToLower(text), forbidden) {
				t.Fatalf("%s contains forbidden inline asset/handler %q", name, forbidden)
			}
		}
	}
}

func TestPublicHomeUsesSharedLocalizedTemplateLayout(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "ru-RU")
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("home status = %d", res.Code)
	}
	body := res.Body.String()
	for _, want := range []string{`<html lang="ru">`, `/static/app.css`, "Verstak Sync"} {
		if !strings.Contains(body, want) {
			t.Fatalf("home is missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "<style>") {
		t.Fatalf("home must use embedded static CSS, not inline style: %s", body)
	}
}

func TestLocaleSelectionUsesCookieAndPRG(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	req := httptest.NewRequest(http.MethodPost, "/locale", strings.NewReader("locale=ru&from=/login"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/login" {
		t.Fatalf("locale response = %d %q", res.Code, res.Header().Get("Location"))
	}
	cookie := res.Result().Cookies()[0]
	if cookie.Name != webLocaleCookieName || cookie.Value != "ru" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected locale cookie: %#v", cookie)
	}
}

func TestLocaleSelectionPreservesResetQuery(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	req := httptest.NewRequest(http.MethodPost, "/locale", strings.NewReader("locale=ru&from=/reset%3Ftoken%3Dopaque-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/reset?token=opaque-token" {
		t.Fatalf("locale redirect=%d %q", res.Code, res.Header().Get("Location"))
	}
}

func TestWebResponsesHaveSecurityHeaders(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/login", nil))
	for name, value := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"} {
		if got := res.Header().Get(name); got != value {
			t.Fatalf("%s=%q, want %q", name, got, value)
		}
	}
	if got := res.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("CSP=%q", got)
	}
}

func TestAdminLoginUsesSharedTemplateAndAdminRootRedirects(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "/static/app.css") || strings.Contains(login.Body.String(), "<style>") {
		t.Fatalf("admin login did not use shared template: %d %s", login.Code, login.Body.String())
	}
	root := httptest.NewRecorder()
	s.Handler().ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if root.Code != http.StatusFound || root.Header().Get("Location") != "/admin/dashboard" {
		t.Fatalf("admin root=%d %q", root.Code, root.Header().Get("Location"))
	}
}

func TestResolveWebLocaleSystemUsesAcceptLanguageAndFallsBack(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Web.DefaultLocale = "en"
	for _, test := range []struct {
		name   string
		cookie string
		header string
		want   string
	}{
		{"system russian", "system", "ru-RU,ru;q=0.9", "ru"},
		{"unknown cookie", "de", "ru-RU", "en"},
		{"no header", "system", "", "en"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.Header.Set("Accept-Language", test.header)
			req.AddCookie(&http.Cookie{Name: webLocaleCookieName, Value: test.cookie})
			if got := resolveWebLocale(req, cfg); got != test.want {
				t.Fatalf("locale = %q, want %q", got, test.want)
			}
		})
	}
}
