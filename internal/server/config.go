package server

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type AdminUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

type Config struct {
	// Port remains readable for older config.yml files. New deployments use
	// Listen so an administrator must deliberately expose a non-loopback
	// listener.
	Port                    int         `yaml:"port,omitempty"`
	Listen                  string      `yaml:"listen,omitempty"`
	TrustedProxies          []string    `yaml:"trusted_proxies,omitempty"`
	PublicURL               string      `yaml:"public_url,omitempty"`
	DevelopmentTokenLogging bool        `yaml:"development_token_logging,omitempty"`
	Web                     WebConfig   `yaml:"web,omitempty"`
	Limits                  Limits      `yaml:"limits,omitempty"`
	Retention               Retention   `yaml:"retention,omitempty"`
	Admin                   []AdminUser `yaml:"admin"`
	mu                      sync.Mutex
	path                    string
	trustedProxyPrefixes    []netip.Prefix
}

// WebConfig intentionally contains only presentation policy. It never
// duplicates transport limits or security configuration owned by the server.
type WebConfig struct {
	DefaultLocale     string `yaml:"default_locale,omitempty"`
	AllowRegistration bool   `yaml:"allow_registration,omitempty"`
	ServerName        string `yaml:"server_name,omitempty"`
}

// Retention controls data that has no role in reconstructing a vault. Sync
// operations and referenced blobs are deliberately absent: pruning either
// requires a checkpoint protocol or risks making a new device unrecoverable.
type Retention struct {
	IdempotencyHours int `yaml:"idempotency_hours"`
	AuditDays        int `yaml:"audit_days"`
	TempUploadHours  int `yaml:"temp_upload_hours"`
}

// Limits protect the process and operation log independently of a client
// supplied value. They are deliberately conservative defaults for a
// self-hosted service and can be adjusted in config.yml.
type Limits struct {
	MaxJSONBody       int64 `yaml:"max_json_body"`
	MaxPushOperations int   `yaml:"max_push_operations"`
	MaxPayloadJSON    int   `yaml:"max_payload_json"`
	MaxPullPage       int   `yaml:"max_pull_page"`
	MaxBlobBytes      int64 `yaml:"max_blob_bytes"`
	MaxVaultBlobBytes int64 `yaml:"max_vault_blob_bytes"`
	MaxUserBlobBytes  int64 `yaml:"max_user_blob_bytes"`
}

func defaultLimits() Limits {
	return Limits{
		MaxJSONBody:       2 << 20,
		MaxPushOperations: 100,
		MaxPayloadJSON:    256 << 10,
		MaxPullPage:       100,
		MaxBlobBytes:      256 << 20,
		MaxVaultBlobBytes: 4 << 30,
		MaxUserBlobBytes:  8 << 30,
	}
}

// DefaultConfig is the safe baseline used by a new server and tests.
func DefaultConfig() *Config {
	return &Config{
		Port:      47732,
		Listen:    "127.0.0.1:47732",
		Web:       WebConfig{DefaultLocale: "en", AllowRegistration: true, ServerName: "Verstak Sync Server"},
		Limits:    defaultLimits(),
		Retention: Retention{IdempotencyHours: 24, AuditDays: 90, TempUploadHours: 24},
	}
}

func LoadConfig(dataDir string) (*Config, error) {
	path := filepath.Join(dataDir, "config.yml")
	cfg := DefaultConfig()
	cfg.path = path
	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ListenAddress returns a loopback address unless an administrator explicitly
// configured another address. A legacy port-only config is also loopback.
func (c *Config) ListenAddress() string {
	if c == nil {
		return "127.0.0.1:47732"
	}
	if listen := strings.TrimSpace(c.Listen); listen != "" {
		return listen
	}
	port := c.Port
	if port == 0 {
		port = 47732
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func (c *Config) normalize() error {
	if c.Port == 0 {
		c.Port = 47732
	}
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = fmt.Sprintf("127.0.0.1:%d", c.Port)
	}
	defaults := defaultLimits()
	if c.Limits.MaxJSONBody <= 0 {
		c.Limits.MaxJSONBody = defaults.MaxJSONBody
	}
	if c.Limits.MaxPushOperations <= 0 {
		c.Limits.MaxPushOperations = defaults.MaxPushOperations
	}
	if c.Limits.MaxPayloadJSON <= 0 {
		c.Limits.MaxPayloadJSON = defaults.MaxPayloadJSON
	}
	if c.Limits.MaxPullPage <= 0 {
		c.Limits.MaxPullPage = defaults.MaxPullPage
	}
	if c.Limits.MaxBlobBytes <= 0 {
		c.Limits.MaxBlobBytes = defaults.MaxBlobBytes
	}
	if c.Limits.MaxVaultBlobBytes <= 0 {
		c.Limits.MaxVaultBlobBytes = defaults.MaxVaultBlobBytes
	}
	if c.Limits.MaxUserBlobBytes <= 0 {
		c.Limits.MaxUserBlobBytes = defaults.MaxUserBlobBytes
	}
	if c.Retention.IdempotencyHours <= 0 {
		c.Retention.IdempotencyHours = 24
	}
	if c.Retention.AuditDays <= 0 {
		c.Retention.AuditDays = 90
	}
	if c.Retention.TempUploadHours <= 0 {
		c.Retention.TempUploadHours = 24
	}
	if !isSupportedWebLocale(c.Web.DefaultLocale) {
		c.Web.DefaultLocale = "en"
	}
	if strings.TrimSpace(c.Web.ServerName) == "" {
		c.Web.ServerName = "Verstak Sync Server"
	}
	prefixes := make([]netip.Prefix, 0, len(c.TrustedProxies))
	for _, raw := range c.TrustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, addrErr := netip.ParseAddr(raw)
			if addrErr != nil {
				return fmt.Errorf("trusted proxy %q is neither an IP address nor CIDR: %w", raw, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	c.trustedProxyPrefixes = prefixes
	return nil
}

// Normalize applies safe defaults and validates proxy configuration after
// command-line and environment overrides.
func (c *Config) Normalize() error {
	return c.normalize()
}

func (c *Config) isTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range c.trustedProxyPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) SetAdmin(username, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := AdminUser{Username: username, PasswordHash: string(hash)}
	for i, u := range c.Admin {
		if u.Username == username {
			c.Admin[i] = user
			return c.saveLocked()
		}
	}
	c.Admin = append(c.Admin, user)
	return c.saveLocked()
}

func (c *Config) CheckAdmin(username, password string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range c.Admin {
		if u.Username == username {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
				return true
			}
		}
	}
	return false
}

func (c *Config) saveLocked() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path)
}
