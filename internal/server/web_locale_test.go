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

func TestFormatWebTimeUsesSelectedLocale(t *testing.T) {
	stamp := "2026-07-17T13:45:00Z"
	if got := formatWebTime("ru", stamp); !strings.Contains(got, "17.07.2026") {
		t.Fatalf("Russian timestamp = %q", got)
	}
	if got := formatWebTime("en", stamp); !strings.Contains(got, "Jul 17, 2026") {
		t.Fatalf("English timestamp = %q", got)
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

func TestConfirmationUsesLocalDialogInsteadOfBrowserPrompt(t *testing.T) {
	layout, err := webFS.ReadFile("web/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := webFS.ReadFile("web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), `id="confirm-dialog"`) || !strings.Contains(string(script), ".showModal()") || strings.Contains(string(script), "window.confirm") {
		t.Fatalf("local confirmation dialog is missing or browser prompt remains")
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

func TestSharedHeaderReflectsAuthenticationScope(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES ('u1','alice','alice@example.test','hash',1,'2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	userToken, userCSRF, err := s.createSession(sessionScopeUser, "u1")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, adminCSRF, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, cookie, token, csrf, dashboard, logout string
		guest                                              bool
	}{
		{name: "guest", path: "/", guest: true},
		{name: "user", path: "/dashboard", cookie: "user_session", token: userToken, csrf: userCSRF, dashboard: "/dashboard", logout: "/logout"},
		{name: "admin", path: "/admin/dashboard", cookie: "admin_session", token: adminToken, csrf: adminCSRF, dashboard: "/admin/dashboard", logout: "/admin/logout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: tc.cookie, Value: tc.token})
				req.AddCookie(&http.Cookie{Name: "csrf_token", Value: tc.csrf})
			}
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", res.Code, res.Body.String())
			}
			body := res.Body.String()
			localeAt := strings.Index(body, `class="locale-form"`)
			if localeAt < 0 {
				t.Fatalf("locale selector is missing: %s", body)
			}
			if tc.guest {
				loginAt := strings.Index(body, `href="/login"`)
				if loginAt < 0 || !strings.Contains(body, `href="/register"`) || localeAt > loginAt {
					t.Fatalf("guest navigation is missing or ordered incorrectly: %s", body)
				}
				return
			}
			if strings.Contains(body, `href="/login"`) || strings.Contains(body, `href="/register"`) {
				t.Fatalf("authenticated header still offers guest authentication: %s", body)
			}
			if !strings.Contains(body, `href="`+tc.dashboard+`"`) || !strings.Contains(body, `action="`+tc.logout+`"`) {
				t.Fatalf("authenticated navigation is incomplete: %s", body)
			}
			if strings.Count(body, `action="`+tc.logout+`"`) != 1 {
				t.Fatalf("logout is duplicated: %s", body)
			}
		})
	}
}

func TestAuthenticatedLoginRedirectsToMatchingDashboard(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	for _, tc := range []struct{ path, cookie, scope, subject, want string }{
		{path: "/login", cookie: "user_session", scope: sessionScopeUser, subject: "u1", want: "/dashboard"},
		{path: "/admin/login", cookie: "admin_session", scope: sessionScopeAdmin, subject: "admin", want: "/admin/dashboard"},
	} {
		token, _, err := s.createSession(tc.scope, tc.subject)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.AddCookie(&http.Cookie{Name: tc.cookie, Value: token})
		res := httptest.NewRecorder()
		s.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusFound || res.Header().Get("Location") != tc.want {
			t.Fatalf("%s = %d %q, want redirect to %s", tc.path, res.Code, res.Header().Get("Location"), tc.want)
		}
	}
}

func TestAdminUsersUseManagementDialogs(t *testing.T) {
	body, err := webFS.ReadFile("web/templates/admin_users.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"<details", "<summary"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("user table still contains %s", forbidden)
		}
	}
	for _, want := range []string{`data-dialog-open="user-dialog-{{.ID}}"`, `id="user-dialog-{{.ID}}"`, `data-dialog-close`, `value="edit-user"`, `value="toggle-user"`, `value="reset-user-password"`, `value="delete-user"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("user dialog contract is missing %q", want)
		}
	}
}

func TestPublicHomeUsesUnavailablePageWhenReadinessFails(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	s.SetupRoutes()
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), `<html lang="en">`) {
		t.Fatalf("unavailable page=%d: %s", res.Code, res.Body.String())
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

func TestAdminPagesRenderWithActiveNavigationInBothLocales(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES ('u1','alice','alice@example.test','hash',1,'2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO server_devices (id,name,api_key,user_id,vault_id,created_at) VALUES ('d1','Laptop','legacy','u1','vault-a','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"ru", "en"} {
		for _, tc := range []struct{ path, active string }{
			{"/admin/dashboard", "/admin/dashboard"}, {"/admin/users", "/admin/users"}, {"/admin/devices", "/admin/devices"}, {"/admin/vaults", "/admin/vaults"}, {"/admin/vault/?user=u1&vault=vault-a", "/admin/vaults"}, {"/admin/storage", "/admin/storage"}, {"/admin/audit", "/admin/audit"}, {"/admin/settings", "/admin/settings"}, {"/admin/diagnostics", "/admin/diagnostics"},
		} {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
			req.AddCookie(&http.Cookie{Name: webLocaleCookieName, Value: locale})
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `<html lang="`+locale+`">`) || !strings.Contains(res.Body.String(), `href="`+tc.active+`" aria-current="page"`) {
				t.Fatalf("%s %s = %d; active navigation missing: %s", locale, tc.path, res.Code, res.Body.String())
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
	req := httptest.NewRequest(http.MethodPost, "/locale", strings.NewReader("locale=ru&from=/login&locale_csrf=locale-test-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webLocaleCSRFCookieName, Value: "locale-test-token"})
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
	req := httptest.NewRequest(http.MethodPost, "/locale", strings.NewReader("locale=ru&from=/reset%3Ftoken%3Dopaque-token&locale_csrf=locale-test-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webLocaleCSRFCookieName, Value: "locale-test-token"})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/reset?token=opaque-token" {
		t.Fatalf("locale redirect=%d %q", res.Code, res.Header().Get("Location"))
	}
}

func TestLocaleSelectionRejectsMissingOrMismatchedCSRF(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	for _, tc := range []struct {
		name, body, cookie string
	}{
		{"missing", "locale=ru&from=/login", ""},
		{"mismatched", "locale=ru&from=/login&locale_csrf=other", "locale-test-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/locale", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: webLocaleCSRFCookieName, Value: tc.cookie})
			}
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code != http.StatusForbidden {
				t.Fatalf("locale CSRF status=%d, want 403", res.Code)
			}
		})
	}
}

func TestPublicWebFormsRejectMissingCSRF(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	for _, path := range []string{"/register", "/login", "/forgot", "/reset", "/admin/login"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("username=alice&email=alice%40example.test&password=password&confirm=password"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		s.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusForbidden {
			t.Fatalf("%s without public CSRF = %d, want 403", path, res.Code)
		}
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

func TestAdminSettingsRendersAndSavesSMTPConfiguration(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.cfg.SetAdmin("admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	s.SetupRoutes()
	token, csrf, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	get.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	get.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	getResult := httptest.NewRecorder()
	s.Handler().ServeHTTP(getResult, get)
	if getResult.Code != http.StatusOK {
		t.Fatalf("settings page = %d: %s", getResult.Code, getResult.Body.String())
	}
	for _, field := range []string{"smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_security", "smtp_from", "server_url"} {
		if !strings.Contains(getResult.Body.String(), `name="`+field+`"`) {
			t.Fatalf("settings page is missing SMTP field %q: %s", field, getResult.Body.String())
		}
	}

	body := "csrf_token=" + csrf + "&action=smtp&smtp_host=mail.example.test&smtp_port=587&smtp_user=mailer&smtp_pass=mail-secret&smtp_security=starttls&smtp_from=sync%40example.test&server_url=https%3A%2F%2Fsync.example.test&password=correct+horse+battery+staple"
	post := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(body))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	post.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	postResult := httptest.NewRecorder()
	s.Handler().ServeHTTP(postResult, post)
	if postResult.Code != http.StatusSeeOther || postResult.Header().Get("Location") != "/admin/settings?flash=smtp_saved" {
		t.Fatalf("save SMTP = %d %q: %s", postResult.Code, postResult.Header().Get("Location"), postResult.Body.String())
	}
	if got := s.smtpGet("smtp_host"); got != "mail.example.test" {
		t.Fatalf("saved SMTP host = %q", got)
	}
}

func TestUserDashboardOnlyRendersOwnFilteredDevices(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	for _, user := range []struct{ id, name string }{{"user-a", "alice"}, {"user-b", "bob"}} {
		if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES (?, ?, ?, 'hash', 1, '2026-01-01T00:00:00Z')", user.id, user.name, user.name+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, device := range []struct{ id, user, name string }{{"device-a", "user-a", "Alice laptop"}, {"device-b", "user-b", "Bob workstation"}} {
		if _, err := s.db.Exec("INSERT INTO server_devices (id,name,api_key,user_id,vault_id,created_at) VALUES (?, ?, ?, ?, 'vault', '2026-01-01T00:00:00Z')", device.id, device.name, "key-"+device.id, device.user); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("INSERT INTO server_user_devices (user_id,device_id) VALUES (?,?)", device.user, device.id); err != nil {
			t.Fatal(err)
		}
	}
	token, _, err := s.createSession(sessionScopeUser, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard?q=Alice", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("dashboard=%d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Alice laptop") || strings.Contains(res.Body.String(), "Bob workstation") {
		t.Fatalf("dashboard leaked or missed device: %s", res.Body.String())
	}
}

func TestAdminDeviceFiltersAndAuditSearchRemainBounded(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, user := range []struct{ id, name string }{{"u1", "alice"}, {"u2", "bob"}} {
		if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES (?, ?, ?, 'hash', 1, '2026-01-01T00:00:00Z')", user.id, user.name, user.name+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, device := range []struct{ id, user, vault, version string }{{"d1", "u1", "vault-a", "2.0"}, {"d2", "u2", "vault-b", "1.0"}} {
		if _, err := s.db.Exec("INSERT INTO server_devices (id,name,api_key,user_id,vault_id,client_version,created_at) VALUES (?, ?, ?, ?, ?, ?, '2026-01-01T00:00:00Z')", device.id, device.id, "key-"+device.id, device.user, device.vault, device.version); err != nil {
			t.Fatal(err)
		}
	}
	devices, list, err := s.webAdminDevices(webList{User: "alice", Vault: "vault-a", Version: "2.0", Sort: "name", Page: 1, PerPage: 25})
	if err != nil || len(devices) != 1 || devices[0].ID != "d1" || list.Sort != "name" {
		t.Fatalf("filtered devices=%+v list=%+v err=%v", devices, list, err)
	}
	if _, err := s.db.Exec("INSERT INTO server_audit_log (event_type,user_id,message,created_at) VALUES ('device_paired','u1','safe','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	audit, _, err := s.webAudit(webList{Event: "' OR 1=1 --", Page: 1, PerPage: 25})
	if err != nil || len(audit) != 0 {
		t.Fatalf("audit injection filter returned=%+v err=%v", audit, err)
	}
}

func TestAdminCanConfirmUnconfirmedUserWithCSRFAndReauth(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.cfg.SetAdmin("admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	s.SetupRoutes()
	if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES ('u1','alice','alice@example.test','hash',0,'2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	token, csrf, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	body := "csrf_token=" + csrf + "&action=confirm-user&id=u1&password=correct+horse+battery+staple"
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/admin/users" {
		t.Fatalf("confirm user=%d %q: %s", res.Code, res.Header().Get("Location"), res.Body.String())
	}
	var confirmed int
	if err := s.db.QueryRow("SELECT confirmed FROM server_users WHERE id='u1'").Scan(&confirmed); err != nil || confirmed != 1 {
		t.Fatalf("confirmed=%d err=%v", confirmed, err)
	}
}

func TestAdminPasswordResetShowsGeneratedSecretOnce(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.cfg.SetAdmin("admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	s.SetupRoutes()
	if _, err := s.db.Exec("INSERT INTO server_users (id,username,email,password_hash,confirmed,created_at) VALUES ('u1','alice','alice@example.test','old',1,'2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	adminToken, csrf, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.createSession(sessionScopeUser, "u1"); err != nil {
		t.Fatal(err)
	}
	body := "csrf_token=" + csrf + "&action=reset-user-password&id=u1&password=correct+horse+battery+staple"
	request := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
	request.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/password-result" {
		t.Fatalf("reset=%d %q: %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	var sessions int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_sessions WHERE scope='user' AND subject_id='u1'").Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("user sessions=%d err=%v", sessions, err)
	}
	resultRequest := httptest.NewRequest(http.MethodGet, "/admin/password-result", nil)
	resultRequest.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
	resultResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(resultResponse, resultRequest)
	if resultResponse.Code != http.StatusOK || !strings.Contains(resultResponse.Header().Get("Cache-Control"), "no-store") || !strings.Contains(resultResponse.Body.String(), "data-one-time-secret-url") {
		t.Fatalf("password result=%d headers=%v body=%s", resultResponse.Code, resultResponse.Header(), resultResponse.Body.String())
	}
	secretRequest := httptest.NewRequest(http.MethodPost, "/admin/password-result/secret", nil)
	secretRequest.Header.Set("X-CSRF-Token", csrf)
	secretRequest.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
	secretRequest.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	secretResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(secretResponse, secretRequest)
	if secretResponse.Code != http.StatusOK || !strings.Contains(secretResponse.Header().Get("Cache-Control"), "no-store") || !strings.Contains(secretResponse.Body.String(), `"password"`) {
		t.Fatalf("secret response=%d headers=%v body=%s", secretResponse.Code, secretResponse.Header(), secretResponse.Body.String())
	}
	secondRequest := httptest.NewRequest(http.MethodPost, "/admin/password-result/secret", nil)
	secondRequest.Header.Set("X-CSRF-Token", csrf)
	secondRequest.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
	secondRequest.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	secondResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusGone {
		t.Fatalf("second password result=%d: %s", secondResponse.Code, secondResponse.Body.String())
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
