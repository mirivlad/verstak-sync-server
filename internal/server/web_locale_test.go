package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
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

func TestEmbeddedTemplateTranslationKeysExist(t *testing.T) {
	entries, err := fs.Glob(webFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	keyPattern := regexp.MustCompile(`t\s+\$?\.Locale\s+"([^"]+)"`)
	for _, name := range entries {
		body, err := webFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range keyPattern.FindAllStringSubmatch(string(body), -1) {
			for _, locale := range []string{"ru", "en"} {
				if _, ok := _translations[locale][match[1]]; !ok {
					t.Fatalf("%s references missing %s translation key %q", name, locale, match[1])
				}
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

func TestPublicTemplateRoutesRenderInBothLocales(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	for _, locale := range []string{"ru", "en"} {
		for _, path := range []string{"/", "/login", "/register", "/forgot", "/admin/login"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{Name: webLocaleCookieName, Value: locale})
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("%s %s = %d", locale, path, res.Code)
			}
			if !strings.Contains(res.Body.String(), `<html lang="`+locale+`">`) {
				t.Fatalf("%s %s has wrong document language", locale, path)
			}
		}
	}
}

func TestConfirmationPageUsesSharedTemplateAndEscapesToken(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/confirm?token=%3Cscript%3E", nil)
	req.AddCookie(&http.Cookie{Name: webLocaleCookieName, Value: "ru"})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `<html lang="ru">`) || strings.Contains(res.Body.String(), "<script>") {
		t.Fatalf("confirmation template/escaping failure: %d %s", res.Code, res.Body.String())
	}
}

func TestNewServerSetsConfigPathInsideDataDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	s, err := NewServer(dir+"/server.db", dir+"/data", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.HasPrefix(cfg.path, dir+"/data/") {
		t.Fatalf("config path escaped data directory: %q", cfg.path)
	}
}

func TestWebSessionScopesDoNotCrossAuthorizePages(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	adminToken, _, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	userToken, _, err := s.createSession(sessionScopeUser, "user")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, cookie string }{{"/dashboard", adminToken}, {"/admin/dashboard", userToken}} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.path == "/dashboard" {
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: tc.cookie})
		} else {
			req.AddCookie(&http.Cookie{Name: "user_session", Value: tc.cookie})
		}
		res := httptest.NewRecorder()
		s.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusFound {
			t.Fatalf("%s with wrong scope = %d", tc.path, res.Code)
		}
	}
}

func TestAdminVaultDetailIsScopedAndDoesNotExposePayload(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES ('u1','alice','a@example.test','hash',1,'2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO server_devices (id,name,api_key,user_id,vault_id,created_at) VALUES ('d1','Laptop','legacy','u1','vault-a','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO server_ops (op_id,server_sequence,user_id,vault_id,device_id,entity_type,entity_id,op_type,payload_json,created_at,pushed_at) VALUES ('op1',1,'u1','vault-a','d1','file','x','create','{\"secret\":\"payload\"}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/vault/?user=u1&vault=vault-a", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("vault detail=%d: %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "payload") || strings.Contains(res.Body.String(), "secret") {
		t.Fatalf("vault detail leaked operation payload: %s", res.Body.String())
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

func TestDiagnosticsDownloadRequiresAdminAndDoesNotExposePaths(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	unauthorized := httptest.NewRecorder()
	s.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/admin/diagnostics.json", nil))
	if unauthorized.Code != http.StatusFound {
		t.Fatalf("unauthorized diagnostics = %d", unauthorized.Code)
	}
	token, _, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/diagnostics.json", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("diagnostics = %d: %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), s.dbPath) || strings.Contains(res.Body.String(), s.blobsDir) {
		t.Fatalf("diagnostics leaked internal path: %s", res.Body.String())
	}
}

func TestAdminUserListSearchStatusAndPagination(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i, username := range []string{"alice", "alina", "blocked-user", "bob"} {
		blocked := 0
		if username == "blocked-user" {
			blocked = 1
		}
		if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,blocked,created_at) VALUES (?, ?, ?, 'hash', 1, ?, '2026-01-01T00:00:00Z')", strconvItoa(i), username, username+"@example.test", blocked); err != nil {
			t.Fatal(err)
		}
	}
	items, list, err := s.webAdminUsers(webList{Query: "ali", Page: 1, PerPage: 1})
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || list.Pages != 2 || len(items) != 1 || items[0].Username != "alice" {
		t.Fatalf("search pagination: list=%+v items=%+v", list, items)
	}
	items, list, err = s.webAdminUsers(webList{Status: "blocked", Page: 1, PerPage: 25})
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(items) != 1 || !items[0].Blocked {
		t.Fatalf("status filter: list=%+v items=%+v", list, items)
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
