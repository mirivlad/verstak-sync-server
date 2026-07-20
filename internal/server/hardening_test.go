package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, error) {
	t.Helper()
	return newServerForTest(t, DefaultConfig())
}

func newServerForTest(t *testing.T, cfg *Config) (*Server, error) {
	t.Helper()
	dir := t.TempDir()
	return NewServer(filepath.Join(dir, "server.db"), filepath.Join(dir, "data"), cfg)
}

func serveJSON(t *testing.T, s *Server, method, path, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	result := make(map[string]interface{})
	if len(res.Body.Bytes()) > 0 {
		if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response: %v (%s)", err, res.Body.String())
		}
	}
	return res.Code, result
}

func insertScopedSyncDevice(t *testing.T, s *Server, deviceID, userID, vaultID, token string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO server_devices
		(id, name, api_key, token_hash, user_id, vault_id, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, deviceID, deviceID, "legacy-"+deviceID, sha256Hex(token), userID, vaultID, now, now); err != nil {
		t.Fatalf("insert scoped device: %v", err)
	}
}

func uploadBlob(t *testing.T, s *Server, token string, data []byte) (int, map[string]interface{}) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "blob.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blobs/", &body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	result := map[string]interface{}{}
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode blob response: %v (%s)", err, res.Body.String())
	}
	return res.Code, result
}

func TestDefaultListenAddressIsLoopback(t *testing.T) {
	cfg := DefaultConfig()
	if got, want := cfg.ListenAddress(), "127.0.0.1:47732"; got != want {
		t.Fatalf("default listen address = %q, want %q", got, want)
	}
}

func TestHTTPServerUsesExplicitTimeouts(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	httpServer := s.HTTPServer("127.0.0.1:0")
	if httpServer.ReadHeaderTimeout <= 0 || httpServer.ReadTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.IdleTimeout <= 0 {
		t.Fatalf("HTTP timeouts must all be set: %#v", httpServer)
	}
	if httpServer.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes must be set: %#v", httpServer)
	}
}

func TestNormalizeEmailAddressRejectsSMTPHeaderInjection(t *testing.T) {
	for _, value := range []string{
		"victim@example.test\r\nBcc: attacker@example.test",
		"Display Name <victim@example.test>",
		"not-an-email",
	} {
		if _, ok := normalizeEmailAddress(value); ok {
			t.Errorf("normalizeEmailAddress(%q) accepted an unsafe address", value)
		}
	}

	if got, ok := normalizeEmailAddress("  User@Example.Test  "); !ok || got != "user@example.test" {
		t.Fatalf("normalizeEmailAddress(valid) = %q, %v", got, ok)
	}
}

func TestRegistrationRejectsSMTPHeaderInjection(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()

	status, _ := serveJSON(t, s, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"username": "victim",
		"email":    "victim@example.test\r\nBcc: attacker@example.test",
		"password": "correct horse battery staple",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("registration status = %d, want %d", status, http.StatusBadRequest)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("registration stored %d unsafe user records", count)
	}
}

func TestHTTPServerGracefulShutdown(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := s.HTTPServer(listener.Addr().String())
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()

	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatalf("serve returned %v", err)
	}
}

func TestClientIPIgnoresUntrustedForwardedHeaders(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/client/pair", nil)
	r.RemoteAddr = "198.51.100.20:4040"
	r.Header.Set("X-Forwarded-For", "203.0.113.8")
	if got, want := s.clientIP(r), "198.51.100.20"; got != want {
		t.Fatalf("client IP = %q, want %q", got, want)
	}
}

func TestClientIPUsesTrustedProxyHeadersOnlyForTrustedPeer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = []string{"127.0.0.1/32"}
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/client/pair", nil)
	r.RemoteAddr = "127.0.0.1:4040"
	r.Header.Set("X-Forwarded-For", "203.0.113.8, 127.0.0.1")
	if got, want := s.clientIP(r), "203.0.113.8"; got != want {
		t.Fatalf("client IP = %q, want %q", got, want)
	}
}

func TestRateLimiterRecoversAfterWindow(t *testing.T) {
	now := time.Now().UTC()
	limiter := newRateLimiter(func() time.Time { return now })
	policy := RatePolicy{Limit: 2, Window: time.Minute}
	if allowed, _ := limiter.Allow("198.51.100.1", policy); !allowed {
		t.Fatal("first attempt unexpectedly limited")
	}
	if allowed, _ := limiter.Allow("198.51.100.1", policy); !allowed {
		t.Fatal("second attempt unexpectedly limited")
	}
	if allowed, retryAfter := limiter.Allow("198.51.100.1", policy); allowed || retryAfter <= 0 {
		t.Fatalf("third attempt = allowed:%t retry:%s, want limited with retry", allowed, retryAfter)
	}
	now = now.Add(time.Minute + time.Second)
	if allowed, _ := limiter.Allow("198.51.100.1", policy); !allowed {
		t.Fatal("attempt after window remained limited")
	}
}

func TestRateLimiterMemoryIsBounded(t *testing.T) {
	limiter := newRateLimiter(nil)
	policy := RatePolicy{Limit: 1, Window: time.Hour}
	for i := 0; i < maxRateLimitBuckets+100; i++ {
		if allowed, _ := limiter.Allow(strconvItoa(i), policy); !allowed {
			t.Fatalf("new bucket %d unexpectedly limited", i)
		}
	}
	if got := len(limiter.buckets); got > maxRateLimitBuckets {
		t.Fatalf("rate buckets = %d, want <= %d", got, maxRateLimitBuckets)
	}
}

func TestSyncPushRejectsOversizedJSONBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxJSONBody = 64
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")

	overSizedJSON := append([]byte(`{"ops":[],"padding":"`), bytes.Repeat([]byte("x"), 65)...)
	overSizedJSON = append(overSizedJSON, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync/push", bytes.NewReader(overSizedJSON))
	req.Header.Set("Authorization", "Bearer token-a")
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d: %s", res.Code, http.StatusRequestEntityTooLarge, res.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "request_too_large" {
		t.Fatalf("error body = %#v, want stable request_too_large code", body)
	}
}

func TestSyncPushRejectsOperationCountAboveLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxPushOperations = 1
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")

	body := syncPushBody("device-a", "op-1", "")
	body["ops"] = append(body["ops"].([]map[string]interface{}), map[string]interface{}{
		"op_id": "op-2", "entity_type": "file", "entity_id": "Docs/two.txt", "op_type": "create",
		"payload_json": `{"path":"Docs/two.txt","content":"two"}`, "created_at": "2026-07-10T00:00:00Z",
	})
	status, response := serveJSON(t, s, http.MethodPost, "/api/v1/sync/push", "token-a", body)
	if status != http.StatusRequestEntityTooLarge || response["code"] != "too_many_operations" {
		t.Fatalf("status=%d body=%#v, want 413 too_many_operations", status, response)
	}
}

func TestSyncPushRejectsTrailingJSONAndOversizedPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxPayloadJSON = 32
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")

	data, err := json.Marshal(syncPushBody("device-a", "op-trailing", ""))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync/push", bytes.NewReader(append(data, []byte(` {}`)...)))
	req.Header.Set("Authorization", "Bearer token-a")
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || !bytes.Contains(res.Body.Bytes(), []byte(`"trailing_json"`)) {
		t.Fatalf("trailing JSON status=%d body=%s", res.Code, res.Body.String())
	}

	body := syncPushBody("device-a", "op-large-payload", "")
	body["ops"].([]map[string]interface{})[0]["payload_json"] = `{"path":"Docs/large.txt","content":"this is intentionally longer than the configured payload bound"}`
	status, response := serveJSON(t, s, http.MethodPost, "/api/v1/sync/push", "token-a", body)
	if status != http.StatusRequestEntityTooLarge || response["code"] != "payload_too_large" {
		t.Fatalf("payload limit status=%d body=%#v", status, response)
	}
}

func TestSyncPullPaginationHasNoGapsOrRepeats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxPullPage = 2
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")
	for _, opID := range []string{"op-1", "op-2", "op-3", "op-4", "op-5"} {
		if status, response := serveJSON(t, s, http.MethodPost, "/api/v1/sync/push", "token-a", syncPushBody("device-a", opID, "")); status != http.StatusOK {
			t.Fatalf("push %s status=%d body=%#v", opID, status, response)
		}
	}

	cursor := 0
	var sequences []int
	for page := 0; page < 3; page++ {
		status, response := serveJSON(t, s, http.MethodPost, "/api/v1/sync/pull", "token-a", map[string]int{"since_sequence": cursor, "page_limit": 2})
		if status != http.StatusOK {
			t.Fatalf("pull page %d status=%d body=%#v", page, status, response)
		}
		for _, raw := range response["ops"].([]interface{}) {
			sequences = append(sequences, int(raw.(map[string]interface{})["server_sequence"].(float64)))
		}
		cursor = int(response["page_last_sequence"].(float64))
		if !response["has_more"].(bool) {
			break
		}
	}
	if got, want := len(sequences), 5; got != want {
		t.Fatalf("sequences=%v, want five ordered values", sequences)
	}
	for i, sequence := range sequences {
		if sequence != i+1 {
			t.Fatalf("sequences=%v, want [1 2 3 4 5]", sequences)
		}
	}
}

func TestBlobOwnershipPreventsCrossVaultDownload(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncUser(t, s, "user-b")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "token-a")
	insertScopedSyncDevice(t, s, "device-b", "user-b", "vault-b", "token-b")

	status, uploaded := uploadBlob(t, s, "token-a", []byte("private blob"))
	if status != http.StatusOK {
		t.Fatalf("upload status=%d body=%#v", status, uploaded)
	}
	sha := uploaded["sha256"].(string)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/blobs/"+sha, nil)
	request.Header.Set("Authorization", "Bearer token-b")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-vault download status=%d, want 404: %s", response.Code, response.Body.String())
	}
}

func TestBlobLimitAndQuotaRejectWithoutResidualFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxBlobBytes = 8
	cfg.Limits.MaxVaultBlobBytes = 8
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "token-a")

	tooLarge := []byte("012345678")
	status, body := uploadBlob(t, s, "token-a", tooLarge)
	if status != http.StatusRequestEntityTooLarge || body["code"] != "blob_too_large" {
		t.Fatalf("file limit status=%d body=%#v", status, body)
	}
	sum := sha256.Sum256(tooLarge)
	path := blobPath(s.blobsDir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected oversized blob left physical file: %v", err)
	}

	status, body = uploadBlob(t, s, "token-a", []byte("12345678"))
	if status != http.StatusOK {
		t.Fatalf("first quota upload status=%d body=%#v", status, body)
	}
	quotaCandidate := []byte("abcdefgh")
	status, body = uploadBlob(t, s, "token-a", quotaCandidate)
	if status != http.StatusRequestEntityTooLarge || body["code"] != "quota_exceeded" {
		t.Fatalf("quota status=%d body=%#v", status, body)
	}
	sum = sha256.Sum256(quotaCandidate)
	if _, err := os.Stat(blobPath(s.blobsDir, hex.EncodeToString(sum[:]))); !os.IsNotExist(err) {
		t.Fatalf("quota-rejected blob left physical file: %v", err)
	}
}

func TestBlobUploadIsIdempotentWithinScope(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "token-a")

	data := []byte("same content")
	_, first := uploadBlob(t, s, "token-a", data)
	_, second := uploadBlob(t, s, "token-a", data)
	if first["sha256"] != second["sha256"] || first["size"] != second["size"] {
		t.Fatalf("idempotent uploads differ: first=%#v second=%#v", first, second)
	}
	var refs int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_blob_refs WHERE user_id=? AND vault_id=?", "user-a", "vault-a").Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if refs != 1 {
		t.Fatalf("blob refs = %d, want one", refs)
	}
}

func TestRevokedDeviceCannotUseBlobEndpoints(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "token-a")
	status, uploaded := uploadBlob(t, s, "token-a", []byte("before revoke"))
	if status != http.StatusOK {
		t.Fatalf("upload status=%d body=%#v", status, uploaded)
	}
	if err := s.revokeDevice("device-a", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/blobs/"+uploaded["sha256"].(string), nil)
	request.Header.Set("Authorization", "Bearer token-a")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked blob download status=%d, want 401", response.Code)
	}
}

func TestAdminKeysNeverReturnPlaintextCredential(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "secret-device-token")
	token, _, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/api/keys", nil)
	request.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte("secret-device-token")) || bytes.Contains(response.Body.Bytes(), []byte("api_key")) {
		t.Fatalf("admin keys leaked a credential: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHealthReportsDegradedDatabase(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	s.SetupRoutes()
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !bytes.Contains(response.Body.Bytes(), []byte(`"database_reachable":false`)) {
		t.Fatalf("readiness after db close: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRetentionDoesNotPruneOperations(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Retention.IdempotencyHours = 1
	cfg.Retention.AuditDays = 1
	s, err := newServerForTest(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertSyncDevice(t, s, "device-a", "user-a", "token-a")
	if status, body := serveJSON(t, s, http.MethodPost, "/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-retained", "")); status != http.StatusOK {
		t.Fatalf("push status=%d body=%#v", status, body)
	}
	if err := s.CleanupRetention(time.Now().UTC().Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var ops int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM server_ops").Scan(&ops); err != nil {
		t.Fatal(err)
	}
	if ops != 1 {
		t.Fatalf("retention removed sync operations: %d", ops)
	}
}

func TestWebSessionSurvivesServerRestartAndLogoutInvalidatesIt(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "server.db")
	dataDir := filepath.Join(dir, "data")
	s, err := NewServer(dbPath, dataDir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, err := s.createSession(sessionScopeUser, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewServer(dbPath, dataDir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.SetupRoutes()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	res := httptest.NewRecorder()
	restarted.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusFound {
		t.Fatalf("logout status=%d body=%s", res.Code, res.Body.String())
	}
	if _, ok := restarted.loadSession(token, sessionScopeUser); ok {
		t.Fatal("logout did not invalidate server-side session")
	}
}

func TestAdminMutationRejectsMissingCSRFToken(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	token, csrf, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	missing := httptest.NewRequest(http.MethodDelete, "/admin/api/keys/missing", nil)
	missing.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	missingResult := httptest.NewRecorder()
	s.Handler().ServeHTTP(missingResult, missing)
	if missingResult.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d, want 403", missingResult.Code)
	}

	valid := httptest.NewRequest(http.MethodDelete, "/admin/api/keys/missing", nil)
	valid.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	valid.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	valid.Header.Set("X-CSRF-Token", csrf)
	validResult := httptest.NewRecorder()
	s.Handler().ServeHTTP(validResult, valid)
	if validResult.Code != http.StatusOK {
		t.Fatalf("valid csrf status=%d body=%s", validResult.Code, validResult.Body.String())
	}
}

func TestAdminUserDeletionIsTransactionalAcrossOwnedRows(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetupRoutes()
	insertSyncUser(t, s, "user-a")
	insertScopedSyncDevice(t, s, "device-a", "user-a", "vault-a", "token-a")
	if status, response := serveJSON(t, s, http.MethodPost, "/api/v1/sync/push", "token-a", syncPushBody("device-a", "op-a", "")); status != http.StatusOK {
		t.Fatalf("push status=%d body=%#v", status, response)
	}
	adminToken, csrf, err := s.createSession(sessionScopeAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/admin/api/users/user-a", nil)
	request.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
	request.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	for table, where := range map[string]string{
		"server_users":     "id='user-a'",
		"server_devices":   "user_id='user-a'",
		"server_ops":       "user_id='user-a'",
		"server_blob_refs": "user_id='user-a'",
	} {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE " + where).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s still has %d rows after user deletion", table, count)
		}
	}
}

func TestResetTokenIsHashedAndSingleUse(t *testing.T) {
	s, err := newTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	insertPairableUser(t, s, "user-a", "alice", "correct horse battery staple")
	token, err := issueEmailToken(s.db, "user-a", "reset", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.db.QueryRow("SELECT token_hash FROM server_email_tokens WHERE user_id=?", "user-a").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || stored != emailTokenHash(token) {
		t.Fatalf("stored reset credential is not a token hash: %q", stored)
	}
	if _, err := s.resetPasswordWithToken(token, "a new secure password"); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	if _, err := s.resetPasswordWithToken(token, "another secure password"); err != errResetTokenInvalid {
		t.Fatalf("second reset err=%v, want invalid token", err)
	}
}
