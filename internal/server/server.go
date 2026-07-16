package server

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	db         *sql.DB
	dbPath     string
	cfg        *Config
	blobsDir   string
	mux        *http.ServeMux
	limiter    *rateLimiter
	web        *webRenderer
	startedAt  time.Time
	secretMu   sync.Mutex
	webSecrets map[string]oneTimeWebSecret
}

// Version and BuildCommit are assigned through -ldflags during release builds.
var (
	Version     = "dev"
	BuildCommit = "unknown"
)

func (s *Server) auditLog(eventType, userID, deviceID, ip, msg string) {
	s.db.Exec("INSERT INTO server_audit_log (event_type, user_id, device_id, ip, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		eventType, userID, deviceID, ip, msg, time.Now().UTC().Format(time.RFC3339))
}

func NewServer(dbPath, dataDir string, cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.path == "" {
		cfg.path = filepath.Join(dataDir, "config.yml")
	}
	if err := cfg.normalize(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=rwc", dbPath))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite %s: %w", pragma, err)
		}
	}

	for _, stmt := range strings.Split(serverSchema, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	if err := migrateServerSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	blobsDir := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0750); err != nil {
		db.Close()
		return nil, err
	}

	web, err := newWebRenderer()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("web templates: %w", err)
	}
	s := &Server{
		db:         db,
		dbPath:     dbPath,
		cfg:        cfg,
		blobsDir:   blobsDir,
		limiter:    newRateLimiter(nil),
		web:        web,
		startedAt:  time.Now().UTC(),
		webSecrets: make(map[string]oneTimeWebSecret),
	}
	s.mux = http.NewServeMux()
	return s, nil
}

func (s *Server) SetupRoutes() {
	s.routes()
}

func (s *Server) locale() string {
	if s != nil && s.cfg != nil && isSupportedWebLocale(s.cfg.Web.DefaultLocale) {
		return s.cfg.Web.DefaultLocale
	}
	return "en"
}

func (s *Server) Close() error {
	return s.db.Close()
}

// Handler is the only HTTP entrypoint. Additional request security middleware
// is composed here so tests and production use the same path.
func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

// HTTPServer creates a conservatively configured server suitable for running
// behind nginx or Caddy. It intentionally does not enable TLS itself.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// ListenAndServe exists for callers that do not need to manage lifecycle. The
// command entrypoint uses HTTPServer plus graceful shutdown instead.
func (s *Server) ListenAndServe(addr string) error {
	return s.HTTPServer(addr).ListenAndServe()
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return s.clientIPFromPeer(host, r.Header.Get("X-Forwarded-For"))
}
