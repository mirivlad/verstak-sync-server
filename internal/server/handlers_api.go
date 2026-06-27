package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Verstak Sync Server\n"))
		return
	}
	jsonErr(w, 404, "not found")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"version": "verstak-server/v1",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleClientPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}
	if !s.pairLimit.allow(ip) {
		s.auditLog("rate_limit_exceeded", "", "", ip, "pair rate limit exceeded")
		jsonErr(w, 429, "too many attempts")
		return
	}
	var req struct {
		Login         string `json:"login"`
		Password      string `json:"password"`
		DeviceName    string `json:"device_name"`
		ClientVersion string `json:"client_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "bad json")
		return
	}
	if req.Login == "" || req.Password == "" {
		jsonErr(w, 400, "login and password required")
		return
	}
	if req.DeviceName == "" {
		req.DeviceName = "unknown"
	}
	var userID, hash string
	var confirmed, blocked int
	err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
		req.Login, strings.ToLower(req.Login)).Scan(&userID, &hash, &confirmed, &blocked)
	if err != nil {
		s.auditLog("device_auth_failed", "", "", ip, "pair: user not found: "+req.Login)
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if blocked != 0 {
		s.auditLog("device_auth_failed", userID, "", ip, "pair: user blocked")
		jsonErr(w, 403, "account blocked")
		return
	}
	if confirmed == 0 {
		s.auditLog("device_auth_failed", userID, "", ip, "pair: email not confirmed")
		jsonErr(w, 403, "email not confirmed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		s.auditLog("device_auth_failed", userID, "", ip, "pair: wrong password")
		jsonErr(w, 401, "invalid credentials")
		return
	}
	devID := make([]byte, 12)
	rand.Read(devID)
	deviceID := "dev_" + hex.EncodeToString(devID)
	token, prefix, suffix := genDeviceToken()
	tokenHash := sha256Hex(token)
	now := time.Now().UTC().Format(time.RFC3339)
	apiKey := make([]byte, 20)
	rand.Read(apiKey)
	_, err = s.db.Exec(`INSERT INTO server_devices
		(id, name, api_key, token_hash, token_prefix, token_suffix, user_id, client_version, last_ip, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID, req.DeviceName, hex.EncodeToString(apiKey), tokenHash, prefix, suffix,
		userID, req.ClientVersion, ip, now, now)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.db.Exec("INSERT OR IGNORE INTO server_user_devices (user_id, device_id) VALUES (?, ?)", userID, deviceID)
	s.db.Exec("UPDATE server_users SET last_seen=? WHERE id=?", now, userID)
	s.pairLimit.reset(ip)
	s.auditLog("device_paired", userID, deviceID, ip, "device paired: "+req.DeviceName)
	jsonOK(w, map[string]interface{}{
		"user_id":             userID,
		"device_id":           deviceID,
		"device_token":        token,
		"server_time":         now,
		"initial_sync_cursor": 0,
	})
}

func (s *Server) handleAuthTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "bad json")
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "username and password required")
		return
	}
	var hash string
	var confirmed, blocked int
	err := s.db.QueryRow("SELECT password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
		req.Username, strings.ToLower(req.Username)).Scan(&hash, &confirmed, &blocked)
	if err != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if blocked != 0 {
		jsonErr(w, 403, "account blocked")
		return
	}
	if confirmed == 0 {
		jsonErr(w, 403, "email not confirmed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleClientRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		jsonErr(w, 401, "token required")
		return
	}
	hash := sha256Hex(tok)
	var deviceID, userID string
	err := s.db.QueryRow("SELECT id, user_id FROM server_devices WHERE token_hash=?", hash).Scan(&deviceID, &userID)
	if err != nil {
		jsonErr(w, 401, "invalid token")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.db.Exec("UPDATE server_devices SET revoked_at=? WHERE id=?", now, deviceID)
	s.auditLog("device_revoked", userID, deviceID, r.RemoteAddr, "device revoked by user")
	jsonOK(w, map[string]string{"status": "revoked"})
}

func (s *Server) handleClientRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		jsonErr(w, 401, "token required")
		return
	}
	hash := sha256Hex(tok)
	var curUserID string
	err := s.db.QueryRow("SELECT user_id FROM server_devices WHERE token_hash=?", hash).Scan(&curUserID)
	if err != nil || curUserID == "" {
		jsonErr(w, 401, "invalid token")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.DeviceID == "" || req.Password == "" {
		jsonErr(w, 400, "device_id and password required")
		return
	}
	var pwHash string
	err = s.db.QueryRow("SELECT password_hash FROM server_users WHERE id=?", curUserID).Scan(&pwHash)
	if err != nil {
		jsonErr(w, 403, "access denied")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(req.Password)) != nil {
		jsonErr(w, 403, "wrong password")
		return
	}
	var devUserID string
	err = s.db.QueryRow("SELECT user_id FROM server_devices WHERE id=?", req.DeviceID).Scan(&devUserID)
	if err != nil {
		jsonErr(w, 404, "device not found")
		return
	}
	if devUserID != curUserID {
		jsonErr(w, 403, "device does not belong to you")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.db.Exec("UPDATE server_devices SET revoked_at=? WHERE id=?", now, req.DeviceID)
	s.auditLog("device_revoked", curUserID, req.DeviceID, r.RemoteAddr, "device revoked via API")
	jsonOK(w, map[string]string{"status": "revoked"})
}

func (s *Server) handleClientMe(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		jsonErr(w, 401, "token required")
		return
	}
	hash := sha256Hex(tok)
	var deviceID, userID, name, clientVer, lastSeen, revokedAt, createdAt string
	err := s.db.QueryRow(`SELECT d.id, d.user_id, d.name, COALESCE(d.client_version,''), COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at
		FROM server_devices d WHERE d.token_hash=?`, hash).
		Scan(&deviceID, &userID, &name, &clientVer, &lastSeen, &revokedAt, &createdAt)
	if err != nil {
		jsonErr(w, 401, "invalid token")
		return
	}
	var username string
	s.db.QueryRow("SELECT username FROM server_users WHERE id=?", userID).Scan(&username)
	jsonOK(w, map[string]interface{}{
		"device_id":      deviceID,
		"user_id":        userID,
		"username":       username,
		"device_name":    name,
		"client_version": clientVer,
		"last_seen":      lastSeen,
		"revoked_at":     revokedAt,
		"created_at":     createdAt,
	})
}

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	if req.Name == "" {
		jsonErr(w, 400, "name required")
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 401, "username and password required")
		return
	}
	var userID, hash string
	var confirmed, blocked int
	err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
		req.Username, strings.ToLower(req.Username)).Scan(&userID, &hash, &confirmed, &blocked)
	if err != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if blocked != 0 {
		jsonErr(w, 403, "account blocked")
		return
	}
	if confirmed == 0 {
		jsonErr(w, 403, "email not confirmed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	b := make([]byte, 20)
	rand.Read(b)
	apiKey := hex.EncodeToString(b)
	deviceID := apiKey[:12]
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(
		"INSERT INTO server_devices (id, name, api_key, last_seen, created_at) VALUES (?, ?, ?, ?, ?)",
		deviceID, req.Name, apiKey, now, now,
	)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.db.Exec("INSERT OR IGNORE INTO server_user_devices (user_id, device_id) VALUES (?, ?)", userID, deviceID)
	jsonOK(w, map[string]interface{}{
		"device_id": deviceID,
		"api_key":   apiKey,
	})
}

func (s *Server) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		DeviceID       string `json:"device_id"`
		IdempotencyKey string `json:"idempotency_key"`
		Ops            []struct {
			OpID              string `json:"op_id"`
			EntityType        string `json:"entity_type"`
			EntityID          string `json:"entity_id"`
			OpType            string `json:"op_type"`
			PayloadJSON       string `json:"payload_json"`
			ClientSequence    int    `json:"client_sequence"`
			LastSeenServerSeq int    `json:"last_seen_server_seq"`
			CreatedAt         string `json:"created_at"`
		} `json:"ops"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if req.IdempotencyKey != "" {
		var cachedJSON string
		err := s.db.QueryRow("SELECT response_json FROM server_idempotency_keys WHERE idempotency_key=?", req.IdempotencyKey).Scan(&cachedJSON)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(cachedJSON))
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var accepted []string
	var conflicts []map[string]interface{}
	for _, op := range req.Ops {
		if op.OpID == "" || op.EntityType == "" || op.EntityID == "" || op.OpType == "" {
			continue
		}
		if op.LastSeenServerSeq > 0 {
			conflictRows, err := s.db.Query(`
				SELECT op_id, device_id, op_type, server_sequence FROM server_ops
				WHERE entity_type=? AND entity_id=? AND device_id!=?
				  AND server_sequence > ? AND op_type != 'delete'
				ORDER BY server_sequence`, op.EntityType, op.EntityID, req.DeviceID, op.LastSeenServerSeq)
			if err == nil {
				for conflictRows.Next() {
					var cOpID, cDevID, cOpType string
					var cSeq int
					conflictRows.Scan(&cOpID, &cDevID, &cOpType, &cSeq)
					conflicts = append(conflicts, map[string]interface{}{
						"op_id":           cOpID,
						"device_id":       cDevID,
						"op_type":         cOpType,
						"server_sequence": cSeq,
						"entity_type":     op.EntityType,
						"entity_id":       op.EntityID,
					})
				}
				conflictRows.Close()
			}
		}
		res, err := s.db.Exec(
			`INSERT OR IGNORE INTO server_ops (op_id, server_sequence, device_id, entity_type, entity_id, op_type, payload_json, idempotency_key, client_sequence, last_seen_server_seq, created_at, pushed_at)
			 VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			op.OpID, req.DeviceID, op.EntityType, op.EntityID, op.OpType, op.PayloadJSON,
			req.IdempotencyKey, op.ClientSequence, op.LastSeenServerSeq, op.CreatedAt, now,
		)
		if err != nil {
			continue
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		seqRes, err := s.db.Exec("INSERT INTO server_revisions (op_id, device_id) VALUES (?, ?)", op.OpID, req.DeviceID)
		if err != nil {
			continue
		}
		seq, _ := seqRes.LastInsertId()
		s.db.Exec("UPDATE server_ops SET server_sequence=? WHERE op_id=?", seq, op.OpID)
		if op.OpType == "delete" {
			s.db.Exec(`INSERT OR REPLACE INTO server_tombstones (entity_type, entity_id, op_id, deleted_at) VALUES (?, ?, ?, ?)`,
				op.EntityType, op.EntityID, op.OpID, now)
		}
		accepted = append(accepted, op.OpID)
	}
	resp := map[string]interface{}{
		"accepted":  accepted,
		"count":     len(accepted),
		"conflicts": conflicts,
	}
	if req.IdempotencyKey != "" {
		if respJSON, err := json.Marshal(resp); err == nil {
			s.db.Exec("INSERT OR IGNORE INTO server_idempotency_keys (idempotency_key, response_json, created_at) VALUES (?, ?, ?)",
				req.IdempotencyKey, string(respJSON), now)
		}
	}
	jsonOK(w, resp)
}

func (s *Server) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		SinceSequence int `json:"since_sequence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	var serverSeq int
	s.db.QueryRow("SELECT COALESCE(MAX(server_sequence), 0) FROM server_ops").Scan(&serverSeq)
	rows, err := s.db.Query(`
		SELECT op_id, server_sequence, device_id, entity_type, entity_id, op_type, payload_json, created_at
		FROM server_ops
		WHERE server_sequence > ? AND server_sequence IS NOT NULL
		ORDER BY server_sequence`, req.SinceSequence)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type opDTO struct {
		OpID           string `json:"op_id"`
		ServerSequence int    `json:"server_sequence"`
		DeviceID       string `json:"device_id"`
		EntityType     string `json:"entity_type"`
		EntityID       string `json:"entity_id"`
		OpType         string `json:"op_type"`
		PayloadJSON    string `json:"payload_json"`
		CreatedAt      string `json:"created_at"`
	}
	ops := []opDTO{}
	for rows.Next() {
		var o opDTO
		if err := rows.Scan(&o.OpID, &o.ServerSequence, &o.DeviceID, &o.EntityType, &o.EntityID, &o.OpType, &o.PayloadJSON, &o.CreatedAt); err != nil {
			continue
		}
		ops = append(ops, o)
	}
	jsonOK(w, map[string]interface{}{
		"server_sequence": serverSeq,
		"ops":             ops,
	})
}

func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case "POST":
		if err := r.ParseMultipartForm(200 << 20); err != nil {
			jsonErr(w, 400, "multipart error: "+err.Error())
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, 400, "file field required")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			jsonErr(w, 500, "read error")
			return
		}
		hash := sha256Hex(string(data))
		blobDir := filepath.Join(s.blobsDir, hash[:2], hash[2:4])
		if err := os.MkdirAll(blobDir, 0750); err != nil {
			jsonErr(w, 500, "mkdir error")
			return
		}
		blobPath := filepath.Join(blobDir, hash)
		if err := os.WriteFile(blobPath, data, 0640); err != nil {
			jsonErr(w, 500, "write error")
			return
		}
		_ = header
		now := time.Now().UTC().Format(time.RFC3339)
		s.db.Exec("INSERT OR IGNORE INTO server_blobs (sha256, size, created_at) VALUES (?, ?, ?)",
			hash, len(data), now)
		jsonOK(w, map[string]interface{}{
			"sha256": hash,
			"size":   len(data),
		})
	case "GET":
		shaHex := strings.TrimPrefix(r.URL.Path, "/api/v1/blobs/")
		if len(shaHex) != 64 {
			jsonErr(w, 400, "invalid SHA-256")
			return
		}
		blobPath := filepath.Join(s.blobsDir, shaHex[:2], shaHex[2:4], shaHex)
		if _, err := os.Stat(blobPath); os.IsNotExist(err) {
			jsonErr(w, 404, "blob not found")
			return
		}
		data, err := os.ReadFile(blobPath)
		if err != nil {
			jsonErr(w, 500, "read error")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+shaHex+"\"")
		w.Write(data)
	default:
		jsonErr(w, 405, "method not allowed")
	}
}
