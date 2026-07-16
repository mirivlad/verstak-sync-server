package server

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed web/templates/*.html web/static/*
var webFS embed.FS

type webRenderer struct {
	templates map[string]*template.Template
	static    fs.FS
}

type webPage struct {
	Locale            string
	LocalePreference  string
	DefaultLocale     string
	Title             string
	ServerName        string
	PublicURL         string
	TrustedProxies    string
	Limits            Limits
	CurrentPath       string
	CurrentURL        string
	CSRF              string
	LocaleCSRF        string
	Flash             string
	FlashError        bool
	AllowRegistration bool
	Version           string
	BuildCommit       string
	Now               time.Time
	Heading           string
	Message           string
	Status            string
	FormAction        string
	BackURL           string
	Token             string
	Admin             bool
	UserName          string
	Email             string
	UserConfirmed     bool
	Devices           []webDevice
	AdminPage         string
	Stats             ServerStats
	Health            HealthStatus
	AdminUsers        []webAdminUser
	AdminDevices      []webAdminDevice
	Vaults            []webVault
	VaultDevices      []webAdminDevice
	Audit             []webAudit
	Warnings          []string
	SMTP              webSMTP
	List              webList
	VaultDetail       webVaultDetail
}

type webAdminUser struct {
	ID, Username, Email, CreatedAt, LastSeen string
	Confirmed, Blocked                       bool
	Devices, Vaults                          int
}
type webAdminDevice struct {
	ID, Name, User, Vault, Version, LastIP, LastSeen, CreatedAt, TokenHint string
	Revoked                                                                bool
}
type webVault struct {
	User, UserID, Vault string
	Devices, Operations int
	LastActivity        string
}
type webAudit struct{ Event, User, Device, IP, Message, Severity, At string }
type webSMTP struct{ Host, Port, User, Security, From, ServerURL string }

type webList struct {
	Query, Status, Sort, User, Vault, Version, Event, Severity string
	Page                                                       int
	PerPage                                                    int
	Total                                                      int
	Pages                                                      int
	Previous                                                   int
	Next                                                       int
}

func (list webList) params(page int) string {
	values := url.Values{}
	for key, value := range map[string]string{"q": list.Query, "status": list.Status, "sort": list.Sort, "user": list.User, "vault": list.Vault, "version": list.Version, "event": list.Event, "severity": list.Severity} {
		if value != "" {
			values.Set(key, value)
		}
	}
	if page > 1 {
		values.Set("page", strconvItoa(page))
	}
	if list.PerPage != 25 {
		values.Set("per_page", strconvItoa(list.PerPage))
	}
	return values.Encode()
}

type webVaultDetail struct {
	User, Vault, LastActivity string
	Devices, Active, Revoked  int
	Operations, Sequence      int
	BlobBytes                 int64
}

type webDevice struct {
	ID            string
	Name          string
	Vault         string
	ClientVersion string
	CreatedAt     string
	LastSeen      string
	Revoked       bool
	TokenHint     string
}

func newWebRenderer() (*webRenderer, error) {
	funcs := template.FuncMap{
		"t":           func(locale, key string) string { return t(locale, key) },
		"webtime":     func(locale, value string) string { return formatWebTime(locale, value) },
		"webbytes":    func(value int64) string { return formatWebBytes(value) },
		"listparams":  func(list webList, page int) string { return list.params(page) },
		"auditlabel":  func(locale, event string) string { return auditEventLabel(locale, event) },
		"statuslabel": func(locale, status string) string { return statusLabel(locale, status) },
		"boollabel":   func(locale string, value bool) string { return boolLabel(locale, value) },
		"short": func(value string, length int) string {
			if len(value) <= length || length < 5 {
				return value
			}
			return value[:length-1] + "…"
		},
	}
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(webFS, "web/templates/layout.html", "web/templates/admin_nav.html")
	if err != nil {
		return nil, err
	}
	renderer := &webRenderer{templates: make(map[string]*template.Template)}
	for _, page := range []string{"home", "unavailable", "login", "register", "forgot", "reset", "confirm", "message", "error", "admin_login", "dashboard", "admin_dashboard", "admin_users", "admin_devices", "admin_vaults", "admin_storage", "admin_audit", "admin_diagnostics", "admin_create_user", "admin_password_result", "vault_detail", "admin_settings"} {
		clone, err := layout.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := clone.ParseFS(webFS, "web/templates/"+page+".html"); err != nil {
			return nil, err
		}
		renderer.templates[page] = clone
	}
	renderer.static, err = fs.Sub(webFS, "web/static")
	if err != nil {
		return nil, err
	}
	return renderer, nil
}

func formatWebTime(locale, value string) string {
	if value == "" {
		return "—"
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	if locale == "ru" {
		return parsed.Local().Format("02.01.2006 15:04")
	}
	return parsed.Local().Format("Jan 2, 2006 15:04")
}

func formatWebBytes(value int64) string {
	if value < 1024 {
		return strconvItoa(int(value)) + " B"
	}
	units := []string{"KB", "MB", "GB", "TB"}
	amount := float64(value)
	for _, unit := range units {
		amount /= 1024
		if amount < 1024 || unit == "TB" {
			return strconv.FormatFloat(amount, 'f', 1, 64) + " " + unit
		}
	}
	return "0 B"
}

func auditEventLabel(locale, event string) string {
	keys := map[string]string{
		"device_auth_failed":    "audit.deviceAuthFailed",
		"device_paired":         "audit.devicePaired",
		"device_revoked":        "audit.deviceRevoked",
		"device_deleted":        "audit.deviceDeleted",
		"rate_limit_exceeded":   "audit.rateLimited",
		"retention_cleanup":     "audit.retentionCleanup",
		"smtp_settings_updated": "audit.smtpSettingsUpdated",
		"smtp_test_failed":      "audit.smtpTestFailed",
		"smtp_test_passed":      "audit.smtpTestPassed",
		"user_block_changed":    "audit.userBlockChanged",
		"user_confirmed":        "audit.userConfirmed",
		"user_created":          "audit.userCreated",
		"user_deleted":          "audit.userDeleted",
		"user_password_reset":   "audit.userPasswordReset",
		"user_updated":          "audit.userUpdated",
		"web_settings_updated":  "audit.webSettingsUpdated",
	}
	if key := keys[event]; key != "" {
		return t(locale, key)
	}
	return t(locale, "audit.other")
}

func statusLabel(locale, status string) string {
	if status == "ok" {
		return t(locale, "status.ok")
	}
	return t(locale, "status.degraded")
}

func boolLabel(locale string, value bool) string {
	if value {
		return t(locale, "status.available")
	}
	return t(locale, "status.unavailable")
}

func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, page string, data webPage) {
	s.renderPageStatus(w, r, page, data, http.StatusOK)
}

func (s *Server) renderPageStatus(w http.ResponseWriter, r *http.Request, page string, data webPage, status int) {
	if s.web == nil || s.web.templates[page] == nil {
		jsonInternalError(w, errWebTemplateUnavailable)
		return
	}
	data.Locale = s.webLocale(r)
	data.LocalePreference = s.webLocalePreference(r)
	data.DefaultLocale = s.cfg.Web.DefaultLocale
	data.ServerName = s.cfg.Web.ServerName
	data.PublicURL = s.cfg.PublicURL
	data.TrustedProxies = strings.Join(s.cfg.TrustedProxies, ", ")
	data.Limits = s.cfg.Limits
	data.CurrentPath = r.URL.Path
	data.CurrentURL = r.URL.RequestURI()
	data.LocaleCSRF = s.webLocaleCSRF(w, r)
	data.AllowRegistration = s.cfg.Web.AllowRegistration
	data.Version = Version
	data.BuildCommit = BuildCommit
	data.Now = time.Now().UTC()
	if cookie, err := r.Cookie("csrf_token"); err == nil {
		data.CSRF = cookie.Value
	}
	if data.Admin || data.UserName != "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	if err := s.web.templates[page].ExecuteTemplate(w, page, data); err != nil {
		jsonInternalError(w, err)
	}
}

var errWebTemplateUnavailable = &webTemplateError{}

type webTemplateError struct{}

func (*webTemplateError) Error() string { return "web template unavailable" }

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(s.web.static))).ServeHTTP(w, r)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.handleNotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	status := s.healthStatus(r.Context())
	if status.Status != "ok" {
		s.renderPageStatus(w, r, "unavailable", webPage{Title: "home.unavailableTitle", Heading: "home.unavailableTitle", Message: "home.unavailableMessage"}, http.StatusServiceUnavailable)
		return
	}
	s.renderPage(w, r, "home", webPage{Title: "home.title", Status: status.Status})
}

func (s *Server) handleLocale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderPage(w, r, "error", webPage{Title: "error.badRequest", Heading: "error.badRequest", Message: "error.tryAgain"})
		return
	}
	if !s.verifyWebLocaleCSRF(r) {
		s.renderPageStatus(w, r, "error", webPage{Title: "error.label", Heading: "error.badRequest", Message: "error.tryAgain", BackURL: "/"}, http.StatusForbidden)
		return
	}
	locale := r.FormValue("locale")
	if locale != "ru" && locale != "en" && locale != "system" {
		locale = "system"
	}
	s.setWebLocale(w, r, locale)
	from := r.FormValue("from")
	if !strings.HasPrefix(from, "/") || strings.HasPrefix(from, "//") {
		from = "/"
	}
	http.Redirect(w, r, from, http.StatusSeeOther)
}

func (s *Server) handleRegistrationResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	s.renderPage(w, r, "message", webPage{Title: "register.resultTitle", Heading: "register.resultTitle", Message: "register.resultMessage", BackURL: "/login"})
}

func (s *Server) handleForgotSent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	s.renderPage(w, r, "message", webPage{Title: "forgot.sentTitle", Heading: "forgot.sentTitle", Message: "forgot.sentMessage", BackURL: "/login"})
}

func (s *Server) handleResetDone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.renderPage(w, r, "message", webPage{Title: "reset.doneTitle", Heading: "reset.doneTitle", Message: "reset.doneMessage", BackURL: "/login"})
}

func (s *Server) handleConfirmResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.renderPage(w, r, "message", webPage{Title: "confirm.resultTitle", Heading: "confirm.resultTitle", Message: "confirm.resultMessage", BackURL: "/login"})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
