package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestSyncPushPullStoresSequencedOps(t *testing.T) {
	dir := t.TempDir()
	s, err := NewServer(filepath.Join(dir, "test.db"), filepath.Join(dir, "data"), &Config{Port: 47732})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()
	s.SetupRoutes()

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		"INSERT INTO server_devices (id, name, api_key, last_seen, created_at) VALUES (?, ?, ?, ?, ?)",
		"device-a", "Device A", "api-key", now, now,
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
