package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestNewServer(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Port: 47732}
	s, err := NewServer(dbPath, dataDir, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}

	blobsDir := filepath.Join(dataDir, "blobs")
	if _, err := os.Stat(blobsDir); os.IsNotExist(err) {
		t.Fatal("blobs directory was not created")
	}
}

func TestConfigSetAdmin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	cfg := &Config{Port: 47732, path: cfgPath}

	if err := cfg.SetAdmin("admin", "secret"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	if !cfg.CheckAdmin("admin", "secret") {
		t.Fatal("CheckAdmin should return true for correct password")
	}

	if cfg.CheckAdmin("admin", "wrong") {
		t.Fatal("CheckAdmin should return false for wrong password")
	}

	if cfg.CheckAdmin("unknown", "secret") {
		t.Fatal("CheckAdmin should return false for unknown user")
	}
}

func TestAdminDashboardSMTPSecuritySelectUsesApplicationStyles(t *testing.T) {
	html := adminDashboardHTML("en", 0, 0, "", "", "", "", "starttls", "")

	for _, expected := range []string{
		`<select name="smtp_security" class="form-select">`,
		`.form-select{`,
		`appearance:none`,
		`background-image:linear-gradient`,
		`.form-select option{background:#13131f;color:#e4e4ef}`,
		`.form-select:focus{outline:none;border-color:#6366f1`,
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("SMTP security select is missing application styling %q", expected)
		}
	}
}

func TestSyncPushPullStoresSequencedOps(t *testing.T) {
	dir := t.TempDir()
	s, err := NewServer(filepath.Join(dir, "test.db"), filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()
	s.SetupRoutes()

	insertSyncUser(t, s, "user-a")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		"INSERT INTO server_devices (id, name, api_key, user_id, vault_id, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"device-a", "Device A", "api-key", "user-a", "vault-a", now, now,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	pushBody := map[string]interface{}{
		"device_id": "device-a",
		"ops": []map[string]interface{}{
			{
				"op_id":           "op-1",
				"entity_type":     "file",
				"entity_id":       "Docs/one.txt",
				"op_type":         "create",
				"payload_json":    `{"path":"Docs/one.txt","content":"hello"}`,
				"created_at":      "2026-06-27T00:00:00Z",
				"client_sequence": 1,
			},
		},
	}
	pushResp := postJSON(t, ts.URL+"/api/v1/sync/push", "api-key", pushBody)
	if got := int(pushResp["count"].(float64)); got != 1 {
		t.Fatalf("push count = %d, want 1: %#v", got, pushResp)
	}
	accepted := pushResp["accepted"].([]interface{})
	if len(accepted) != 1 || accepted[0] != "op-1" {
		t.Fatalf("accepted = %#v", accepted)
	}

	pullResp := postJSON(t, ts.URL+"/api/v1/sync/pull", "api-key", map[string]interface{}{
		"since_sequence": 0,
	})
	if got := int(pullResp["server_sequence"].(float64)); got != 1 {
		t.Fatalf("server_sequence = %d, want 1: %#v", got, pullResp)
	}
	ops := pullResp["ops"].([]interface{})
	if len(ops) != 1 {
		t.Fatalf("ops len = %d, want 1: %#v", len(ops), ops)
	}
	op := ops[0].(map[string]interface{})
	if op["op_id"] != "op-1" ||
		op["device_id"] != "device-a" ||
		op["entity_type"] != "file" ||
		op["entity_id"] != "Docs/one.txt" ||
		op["op_type"] != "create" ||
		op["payload_json"] != `{"path":"Docs/one.txt","content":"hello"}` ||
		int(op["server_sequence"].(float64)) != 1 {
		t.Fatalf("pulled op = %#v", op)
	}

	pullAfterResp := postJSON(t, ts.URL+"/api/v1/sync/pull", "api-key", map[string]interface{}{
		"since_sequence": 1,
	})
	if got := int(pullAfterResp["server_sequence"].(float64)); got != 1 {
		t.Fatalf("server_sequence after = %d, want 1", got)
	}
	if ops := pullAfterResp["ops"].([]interface{}); len(ops) != 0 {
		t.Fatalf("ops after seq len = %d, want 0: %#v", len(ops), ops)
	}
}

func TestRevokedLegacyAPIKeyCannotPushOrPull(t *testing.T) {
	dir := t.TempDir()
	s, err := NewServer(filepath.Join(dir, "test.db"), filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()
	s.SetupRoutes()

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		"INSERT INTO server_devices (id, name, api_key, last_seen, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"device-revoked", "Revoked Device", "revoked-key", now, now, now,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	pushStatus, pushResp := postJSONStatus(t, ts.URL+"/api/v1/sync/push", "revoked-key", map[string]interface{}{
		"device_id": "device-revoked",
		"ops":       []map[string]interface{}{},
	})
	if pushStatus != http.StatusUnauthorized || pushResp["error"] != "device revoked" {
		t.Fatalf("push status=%d resp=%#v, want 401 device revoked", pushStatus, pushResp)
	}

	pullStatus, pullResp := postJSONStatus(t, ts.URL+"/api/v1/sync/pull", "revoked-key", map[string]interface{}{
		"since_sequence": 0,
	})
	if pullStatus != http.StatusUnauthorized || pullResp["error"] != "device revoked" {
		t.Fatalf("pull status=%d resp=%#v, want 401 device revoked", pullStatus, pullResp)
	}
}

func TestSyncPullDoesNotExposeOtherUserOperations(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	insertSyncUser(t, s, "user-a")
	insertSyncUser(t, s, "user-b")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")
	insertSyncDevice(t, s, "device-b", "user-b", "token-b")

	postJSON(t, ts.URL+"/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-user-a", ""))

	pull := postJSON(t, ts.URL+"/api/v1/sync/pull", "token-b", map[string]interface{}{
		"since_sequence": 0,
	})
	if got := len(pull["ops"].([]interface{})); got != 0 {
		t.Fatalf("other user pulled %d operation(s), want 0: %#v", got, pull)
	}
	if got := int(pull["server_sequence"].(float64)); got != 0 {
		t.Fatalf("other user cursor = %d, want 0: %#v", got, pull)
	}
}

func TestSyncPushUsesAuthenticatedDeviceIdentity(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	insertSyncUser(t, s, "user-a")
	insertSyncUser(t, s, "user-b")
	insertSyncDevice(t, s, "device-authenticated", "user-a", "token-a")
	insertSyncDevice(t, s, "device-forged", "user-b", "token-b")

	postJSON(t, ts.URL+"/api/v1/sync/push", "token-a", syncPushBody("device-forged", "op-auth-device", ""))

	var storedDeviceID string
	if err := s.db.QueryRow("SELECT device_id FROM server_ops WHERE op_id=?", "op-auth-device").Scan(&storedDeviceID); err != nil {
		t.Fatalf("read stored operation: %v", err)
	}
	if storedDeviceID != "device-authenticated" {
		t.Fatalf("stored device = %q, want authenticated device", storedDeviceID)
	}
}

func TestSyncPushScopesIdempotencyResponsesByUser(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	insertSyncUser(t, s, "user-a")
	insertSyncUser(t, s, "user-b")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")
	insertSyncDevice(t, s, "device-b", "user-b", "token-b")

	postJSON(t, ts.URL+"/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-user-a", "same-key"))
	response := postJSON(t, ts.URL+"/api/v1/sync/push", "token-b", syncPushBody("device-b", "op-user-b", "same-key"))

	accepted := response["accepted"].([]interface{})
	if len(accepted) != 1 || accepted[0] != "op-user-b" {
		t.Fatalf("user-b received idempotency response %#v, want only op-user-b", response)
	}
}

func TestSyncPushDoesNotReportOtherTenantConflicts(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	insertSyncUser(t, s, "user-a")
	insertSyncUser(t, s, "user-b")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")
	insertSyncDevice(t, s, "device-b", "user-b", "token-b")

	postJSON(t, ts.URL+"/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-user-a-1", ""))
	postJSON(t, ts.URL+"/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-user-a-2", ""))

	body := syncPushBody("device-b", "op-user-b", "")
	body["ops"].([]map[string]interface{})[0]["last_seen_server_seq"] = 1
	response := postJSON(t, ts.URL+"/api/v1/sync/push", "token-b", body)
	if response["conflicts"] != nil {
		t.Fatalf("other tenant conflict leaked into response: %#v", response)
	}
}

func TestSyncPullDoesNotExposeOtherVaultOperations(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	password := "correct horse battery staple"
	insertPairableUser(t, s, "user-a", "alice", password)

	deviceA := pairSyncDevice(t, ts.URL, "alice", password, "vault-a")
	deviceB := pairSyncDevice(t, ts.URL, "alice", password, "vault-b")

	postJSON(t, ts.URL+"/api/v1/sync/push", deviceA.token, syncPushBody(deviceA.id, "op-vault-a", ""))
	postJSON(t, ts.URL+"/api/v1/sync/push", deviceB.token, syncPushBody(deviceB.id, "op-vault-b", ""))

	pull := postJSON(t, ts.URL+"/api/v1/sync/pull", deviceA.token, map[string]interface{}{
		"since_sequence": 0,
	})
	ops := pull["ops"].([]interface{})
	if len(ops) != 1 || ops[0].(map[string]interface{})["op_id"] != "op-vault-a" {
		t.Fatalf("vault-a pulled %#v, want only op-vault-a", pull)
	}
}

func TestClientPairRequiresVaultID(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	password := "correct horse battery staple"
	insertPairableUser(t, s, "user-a", "alice", password)

	status, response := postJSONStatus(t, ts.URL+"/api/client/pair", "", map[string]interface{}{
		"login":       "alice",
		"password":    password,
		"device_name": "Desktop",
	})
	if status != http.StatusBadRequest || response["error"] != "vault_id required" {
		t.Fatalf("pair without vault ID status=%d response=%#v, want 400 vault_id required", status, response)
	}
}

func TestClientPairRejectsReservedLegacyVaultID(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	password := "correct horse battery staple"
	insertPairableUser(t, s, "user-a", "alice", password)

	status, response := postJSONStatus(t, ts.URL+"/api/client/pair", "", map[string]interface{}{
		"login":       "alice",
		"password":    password,
		"device_name": "Desktop",
		"vault_id":    "legacy:user-a",
	})
	if status != http.StatusBadRequest || response["error"] != "vault_id uses reserved prefix" {
		t.Fatalf("pair with reserved vault ID status=%d response=%#v, want 400 reserved prefix", status, response)
	}
}

func TestDeviceRegisterRequiresValidVaultID(t *testing.T) {
	s, ts := newSyncHTTPServer(t)
	defer s.Close()
	defer ts.Close()

	password := "correct horse battery staple"
	insertPairableUser(t, s, "user-a", "alice", password)

	status, response := postJSONStatus(t, ts.URL+"/api/v1/device/register", "", map[string]interface{}{
		"name":     "Desktop",
		"username": "alice",
		"password": password,
	})
	if status != http.StatusBadRequest || response["error"] != "vault_id required" {
		t.Fatalf("register without vault ID status=%d response=%#v, want 400 vault_id required", status, response)
	}

	status, response = postJSONStatus(t, ts.URL+"/api/v1/device/register", "", map[string]interface{}{
		"name":     "Desktop",
		"username": "alice",
		"password": password,
		"vault_id": "legacy:user-a",
	})
	if status != http.StatusBadRequest || response["error"] != "vault_id uses reserved prefix" {
		t.Fatalf("register with reserved vault ID status=%d response=%#v, want 400 reserved prefix", status, response)
	}
}

func TestWebResetRejectsExpiredToken(t *testing.T) {
	s, _ := newSyncHTTPServer(t)
	defer s.Close()

	oldPassword := "correct horse battery staple"
	insertPairableUser(t, s, "user-a", "alice", oldPassword)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_email_tokens
		(token, user_id, purpose, expires_at, created_at)
		VALUES (?, ?, 'reset', ?, ?)`, "expired-reset-token", "user-a", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), now); err != nil {
		t.Fatalf("insert reset token: %v", err)
	}

	response := postWebReset(t, s, "expired-reset-token", "new secret password")
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/forgot" {
		t.Fatalf("expired reset response status=%d location=%q, want 302 /forgot", response.Code, response.Header().Get("Location"))
	}

	var passwordHash string
	if err := s.db.QueryRow("SELECT password_hash FROM server_users WHERE id=?", "user-a").Scan(&passwordHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(oldPassword)) != nil {
		t.Fatal("expired reset changed the password")
	}
}

func TestServerRenderedPagesEscapeStoredValues(t *testing.T) {
	s, _ := newSyncHTTPServer(t)
	defer s.Close()

	const maliciousText = `<img src=x onerror=alert(1)>`
	const maliciousDeviceID = `device');alert(1);//`
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_users
		(id, username, email, password_hash, confirmed, created_at)
		VALUES (?, ?, ?, ?, 1, ?)`, "user-a", maliciousText, maliciousText+"@example.test", "unused", now); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO server_devices
		(id, name, api_key, user_id, vault_id, client_version, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, maliciousDeviceID, maliciousText, "device-key", "user-a", "vault-a", maliciousText, now, now); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := s.db.Exec("INSERT INTO server_user_devices (user_id, device_id) VALUES (?, ?)", "user-a", maliciousDeviceID); err != nil {
		t.Fatalf("link user device: %v", err)
	}

	tests := []struct {
		name          string
		path          string
		cookie        *http.Cookie
		containsDevID bool
	}{
		{
			name:          "user dashboard",
			path:          "/dashboard",
			cookie:        &http.Cookie{Name: "user_session", Value: s.userTokens.Create("user-a")},
			containsDevID: true,
		},
		{
			name:   "admin users",
			path:   "/admin/users",
			cookie: &http.Cookie{Name: "admin_session", Value: s.tokens.Create()},
		},
		{
			name:          "admin devices",
			path:          "/admin/devices",
			cookie:        &http.Cookie{Name: "admin_session", Value: s.tokens.Create()},
			containsDevID: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.AddCookie(tt.cookie)
			res := httptest.NewRecorder()
			s.mux.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", res.Code)
			}
			body := res.Body.String()
			if strings.Contains(body, maliciousText) {
				t.Fatalf("page contains unescaped stored text: %s", body)
			}
			if !strings.Contains(body, html.EscapeString(maliciousText)) {
				t.Fatalf("page does not contain escaped stored text: %s", body)
			}
			if tt.containsDevID && strings.Contains(body, maliciousDeviceID) {
				t.Fatalf("page contains unescaped device ID: %s", body)
			}
		})
	}
}

func TestNewServerMigratesLegacyOperationScope(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}

	legacySchema := []string{
		`CREATE TABLE server_devices (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, api_key TEXT NOT NULL UNIQUE,
			token_hash TEXT, token_prefix TEXT, token_suffix TEXT, user_id TEXT,
			client_version TEXT, last_ip TEXT, last_seen TEXT, revoked_at TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE server_user_devices (
			user_id TEXT NOT NULL, device_id TEXT NOT NULL,
			PRIMARY KEY (user_id, device_id)
		)`,
		`CREATE TABLE server_ops (
			op_id TEXT PRIMARY KEY, server_sequence INTEGER, device_id TEXT NOT NULL,
			entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, op_type TEXT NOT NULL,
			payload_json TEXT NOT NULL, idempotency_key TEXT, client_sequence INTEGER DEFAULT 0,
			last_seen_server_seq INTEGER DEFAULT 0, created_at TEXT NOT NULL,
			pushed_at TEXT NOT NULL
		)`,
		`CREATE TABLE server_tombstones (
			entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, op_id TEXT NOT NULL,
			deleted_at TEXT NOT NULL, PRIMARY KEY (entity_type, entity_id)
		)`,
		`CREATE TABLE server_idempotency_keys (
			idempotency_key TEXT PRIMARY KEY, response_json TEXT NOT NULL, created_at TEXT NOT NULL
		)`,
	}
	for _, stmt := range legacySchema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create legacy schema: %v", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO server_devices (id, name, api_key, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?)`, "legacy-device", "Legacy", "legacy-key", now, now); err != nil {
		t.Fatalf("insert legacy device: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO server_user_devices (user_id, device_id) VALUES (?, ?)`, "legacy-user", "legacy-device"); err != nil {
		t.Fatalf("insert legacy device owner: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO server_ops
		(op_id, server_sequence, device_id, entity_type, entity_id, op_type, payload_json, created_at, pushed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, "legacy-op", 1, "legacy-device", "file", "Docs/one.txt", "create", `{}`, now, now); err != nil {
		t.Fatalf("insert legacy operation: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	s, err := NewServer(dbPath, filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer migration: %v", err)
	}
	assertLegacyOperationScope(t, s)
	if err := s.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	s, err = NewServer(dbPath, filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer repeated migration: %v", err)
	}
	defer s.Close()
	assertLegacyOperationScope(t, s)
}

func assertLegacyOperationScope(t *testing.T, s *Server) {
	t.Helper()
	var userID, vaultID string
	if err := s.db.QueryRow("SELECT user_id, vault_id FROM server_ops WHERE op_id=?", "legacy-op").Scan(&userID, &vaultID); err != nil {
		t.Fatalf("read migrated operation: %v", err)
	}
	if userID != "legacy-user" || vaultID != "legacy:legacy-user" {
		t.Fatalf("migrated scope = %q/%q, want legacy-user/legacy:legacy-user", userID, vaultID)
	}
}

func newSyncHTTPServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewServer(filepath.Join(dir, "test.db"), filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.SetupRoutes()
	return s, httptest.NewServer(s.mux)
}

func insertSyncUser(t *testing.T, s *Server, userID string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_users
		(id, username, email, password_hash, confirmed, created_at)
		VALUES (?, ?, ?, ?, 1, ?)`, userID, userID, userID+"@example.test", "unused", now); err != nil {
		t.Fatalf("insert sync user %s: %v", userID, err)
	}
}

func insertPairableUser(t *testing.T, s *Server, userID, username, password string) {
	t.Helper()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_users
		(id, username, email, password_hash, confirmed, created_at)
		VALUES (?, ?, ?, ?, 1, ?)`, userID, username, username+"@example.test", string(passwordHash), now); err != nil {
		t.Fatalf("insert pairable user: %v", err)
	}
}

func insertSyncDevice(t *testing.T, s *Server, deviceID, userID, token string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_devices
		(id, name, api_key, token_hash, user_id, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, deviceID, deviceID, "legacy-"+deviceID, sha256Hex(token), userID, now, now); err != nil {
		t.Fatalf("insert sync device %s: %v", deviceID, err)
	}
}

func syncPushBody(deviceID, opID, idempotencyKey string) map[string]interface{} {
	return map[string]interface{}{
		"device_id":       deviceID,
		"idempotency_key": idempotencyKey,
		"ops": []map[string]interface{}{
			{
				"op_id":        opID,
				"entity_type":  "file",
				"entity_id":    "Docs/one.txt",
				"op_type":      "create",
				"payload_json": `{"path":"Docs/one.txt","content":"hello"}`,
				"created_at":   "2026-07-10T00:00:00Z",
			},
		},
	}
}

type pairedSyncDevice struct {
	id    string
	token string
}

func pairSyncDevice(t *testing.T, serverURL, username, password, vaultID string) pairedSyncDevice {
	t.Helper()
	response := postJSON(t, serverURL+"/api/client/pair", "", map[string]interface{}{
		"login":       username,
		"password":    password,
		"device_name": "Desktop " + vaultID,
		"vault_id":    vaultID,
	})
	return pairedSyncDevice{
		id:    response["device_id"].(string),
		token: response["device_token"].(string),
	}
}

func postWebReset(t *testing.T, s *Server, token, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"token":    {token},
		"password": {password},
		"confirm":  {password},
	}
	request := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.mux.ServeHTTP(response, request)
	return response
}

func postJSON(t *testing.T, url, token string, body interface{}) map[string]interface{} {
	t.Helper()
	status, out := postJSONStatus(t, url, token, body)
	if status != http.StatusOK {
		t.Fatalf("post %s status = %d", url, status)
	}
	return out
}

func postJSONStatus(t *testing.T, url, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(body); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &b)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, out
}
