package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type pairRateLimit struct {
	mu       sync.Mutex
	attempts map[string]int
}

func (p *pairRateLimit) allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attempts == nil {
		p.attempts = make(map[string]int)
	}
	p.attempts[ip]++
	return p.attempts[ip] <= 5
}

func (p *pairRateLimit) reset(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.attempts, ip)
}

type tokenStore struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func newTokenStore() *tokenStore {
	return &tokenStore{tokens: make(map[string]time.Time)}
}

func (ts *tokenStore) Create() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	ts.tokens[tok] = time.Now().Add(24 * time.Hour)
	return tok
}

func (ts *tokenStore) Check(tok string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	exp, ok := ts.tokens[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(ts.tokens, tok)
		return false
	}
	return true
}

type userTokenStore struct {
	mu     sync.Mutex
	tokens map[string]userTokenEntry
}

type userTokenEntry struct {
	UserID    string
	ExpiresAt time.Time
}

func newUserTokenStore() *userTokenStore {
	return &userTokenStore{tokens: make(map[string]userTokenEntry)}
}

func (uts *userTokenStore) Create(userID string) string {
	uts.mu.Lock()
	defer uts.mu.Unlock()
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	uts.tokens[tok] = userTokenEntry{UserID: userID, ExpiresAt: time.Now().Add(24 * time.Hour)}
	return tok
}

func (uts *userTokenStore) Check(tok string) (string, bool) {
	uts.mu.Lock()
	defer uts.mu.Unlock()
	entry, ok := uts.tokens[tok]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(uts.tokens, tok)
		return "", false
	}
	return entry.UserID, true
}

type Server struct {
	db         *sql.DB
	cfg        *Config
	tokens     *tokenStore
	userTokens *userTokenStore
	blobsDir   string
	mux        *http.ServeMux
	pairLimit  *pairRateLimit
}

func (s *Server) auditLog(eventType, userID, deviceID, ip, msg string) {
	s.db.Exec("INSERT INTO server_audit_log (event_type, user_id, device_id, ip, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		eventType, userID, deviceID, ip, msg, time.Now().UTC().Format(time.RFC3339))
}

func NewServer(dbPath, dataDir string, cfg *Config) (*Server, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=rwc", dbPath))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

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

	blobsDir := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0750); err != nil {
		db.Close()
		return nil, err
	}

	s := &Server{
		db:         db,
		cfg:        cfg,
		tokens:     newTokenStore(),
		userTokens: newUserTokenStore(),
		blobsDir:   blobsDir,
		pairLimit:  &pairRateLimit{},
	}
	s.mux = http.NewServeMux()
	return s, nil
}

func (s *Server) SetupRoutes() {
	s.routes()
}

func (s *Server) locale() string {
	return "ru"
}

func (s *Server) Close() error {
	return s.db.Close()
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}
