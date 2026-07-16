package server

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
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
	CurrentPath       string
	CurrentURL        string
	CSRF              string
	Flash             string
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
	Devices           []webDevice
	AdminPage         string
	Stats             ServerStats
	Health            HealthStatus
	AdminUsers        []webAdminUser
	AdminDevices      []webAdminDevice
	Vaults            []webVault
	Audit             []webAudit
	SMTP              webSMTP
	List              webList
	VaultDetail       webVaultDetail
}

type webAdminUser struct {
	ID, Username, Email, CreatedAt, LastSeen string
	Confirmed, Blocked                       bool
	Devices                                  int
}
type webAdminDevice struct {
	ID, Name, User, Vault, Version, LastSeen, CreatedAt string
	Revoked                                             bool
}
type webVault struct {
	User, UserID, Vault string
	Devices, Operations int
	LastActivity        string
}
type webAudit struct{ Event, User, Device, At string }
type webSMTP struct{ Host, Port, User, Security, From, ServerURL string }

type webList struct {
	Query    string
	Status   string
	Page     int
	PerPage  int
	Total    int
	Pages    int
	Previous int
	Next     int
}
type webVaultDetail struct {
	User, Vault, LastActivity string
	Devices, Operations       int
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
		"t": func(locale, key string) string { return t(locale, key) },
		"short": func(value string, length int) string {
			if len(value) <= length || length < 5 {
				return value
			}
			return value[:length-1] + "…"
		},
	}
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(webFS, "web/templates/layout.html")
	if err != nil {
		return nil, err
	}
	renderer := &webRenderer{templates: make(map[string]*template.Template)}
	for _, page := range []string{"home", "login", "register", "forgot", "reset", "confirm", "message", "error", "admin_login", "dashboard", "admin", "admin_create_user", "vault_detail", "admin_settings"} {
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
	data.CurrentPath = r.URL.Path
	data.CurrentURL = r.URL.RequestURI()
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
