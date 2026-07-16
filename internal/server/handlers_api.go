package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
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
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	health := s.healthStatus(r.Context())
	if health.Status != "ok" {
		jsonOKStatus(w, http.StatusServiceUnavailable, health)
		return
	}
	jsonOK(w, health)
}

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	jsonOK(w, map[string]interface{}{"status": "ok", "server_time": time.Now().UTC().Format(time.RFC3339)})
}

func (s *Server) handleClientPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	ip := s.clientIP(r)
	var req struct {
		Login         string `json:"login"`
		Password      string `json:"password"`
		DeviceName    string `json:"device_name"`
		ClientVersion string `json:"client_version"`
		VaultID       string `json:"vault_id"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Login == "" || req.Password == "" {
		jsonErr(w, 400, "login and password required")
		return
	}
	if !s.allowRate(w, r, "pair", req.Login) {
		return
	}
	req.VaultID = strings.TrimSpace(req.VaultID)
	if req.VaultID == "" {
		jsonErr(w, 400, "vault_id required")
		return
	}
	if strings.HasPrefix(req.VaultID, "legacy:") {
		jsonErr(w, 400, "vault_id uses reserved prefix")
		return
	}
	if req.DeviceName == "" {
		req.DeviceName = "unknown"
	}
	if err := validatePairRequest(req.Login, req.DeviceName, req.ClientVersion, req.VaultID); err != nil {
		jsonErrCode(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var userID, hash string
	var confirmed, blocked int
	err := s.db.QueryRow("SELECT id, password_hash, confirmed, blocked FROM server_users WHERE username=? OR email=?",
		req.Login, strings.ToLower(req.Login)).Scan(&userID, &hash, &confirmed, &blocked)
	if err != nil {
		s.auditLog("device_auth_failed", "", "", ip, "pair: user not found")
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
	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO server_devices
		(id, name, api_key, token_hash, token_prefix, token_suffix, legacy_api_key, user_id, vault_id, client_version, last_ip, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
		deviceID, req.DeviceName, "disabled:"+deviceID, tokenHash, prefix, suffix,
		userID, req.VaultID, req.ClientVersion, ip, now, now)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO server_user_devices (user_id, device_id) VALUES (?, ?)", userID, deviceID); err != nil {
		jsonInternalError(w, err)
		return
	}
	if _, err := tx.Exec("UPDATE server_users SET last_seen=? WHERE id=?", now, userID); err != nil {
		jsonInternalError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
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
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "username and password required")
		return
	}
	if !s.allowRate(w, r, "auth-test", req.Username) {
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
	device, ok := s.authenticateDevice(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.revokeDevice(device.DeviceID, now); err != nil {
		jsonInternalError(w, err)
		return
	}
	s.auditLog("device_revoked", device.UserID, device.DeviceID, s.clientIP(r), "device revoked by user")
	jsonOK(w, map[string]string{"status": "revoked"})
}

func (s *Server) handleClientRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	device, ok := s.authenticateDevice(w, r)
	if !ok || device.UserID == "" {
		return
	}
	curUserID := device.UserID
	var req struct {
		DeviceID string `json:"device_id"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.DeviceID == "" || req.Password == "" {
		jsonErr(w, 400, "device_id and password required")
		return
	}
	if !s.allowRate(w, r, "auth-test", curUserID) {
		return
	}
	var pwHash string
	err := s.db.QueryRow("SELECT password_hash FROM server_users WHERE id=?", curUserID).Scan(&pwHash)
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
	if err := s.revokeDevice(req.DeviceID, now); err != nil {
		jsonInternalError(w, err)
		return
	}
	s.auditLog("device_revoked", curUserID, req.DeviceID, s.clientIP(r), "device revoked via API")
	jsonOK(w, map[string]string{"status": "revoked"})
}

func (s *Server) handleClientMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	device, ok := s.authenticateDevice(w, r)
	if !ok {
		return
	}
	var deviceID, userID, name, clientVer, lastSeen, revokedAt, createdAt string
	err := s.db.QueryRow(`SELECT d.id, d.user_id, d.name, COALESCE(d.client_version,''), COALESCE(d.last_seen,''), COALESCE(d.revoked_at,''), d.created_at
		FROM server_devices d WHERE d.id=?`, device.DeviceID).
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
		VaultID  string `json:"vault_id"`
	}
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
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
	if !s.allowRate(w, r, "device-register", req.Username) {
		return
	}
	if err := validatePairRequest(req.Username, req.Name, "", req.VaultID); err != nil {
		jsonErrCode(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.VaultID = strings.TrimSpace(req.VaultID)
	if req.VaultID == "" {
		jsonErr(w, 400, "vault_id required")
		return
	}
	if strings.HasPrefix(req.VaultID, "legacy:") {
		jsonErr(w, 400, "vault_id uses reserved prefix")
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
	b := make([]byte, 12)
	rand.Read(b)
	deviceID := "dev_" + hex.EncodeToString(b)
	token, prefix, suffix := genDeviceToken()
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(
		"INSERT INTO server_devices (id, name, api_key, token_hash, token_prefix, token_suffix, legacy_api_key, user_id, vault_id, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
		deviceID, req.Name, "disabled:"+deviceID, sha256Hex(token), prefix, suffix, userID, req.VaultID, now, now,
	)
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO server_user_devices (user_id, device_id) VALUES (?, ?)", userID, deviceID); err != nil {
		jsonInternalError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]interface{}{
		"device_id":    deviceID,
		"device_token": token,
	})
}

func (s *Server) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}
	scope, ok := s.requireSyncScope(w, r)
	if !ok {
		return
	}
	var req syncPushRequest
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if code, message := s.validateSyncPush(req); code != "" {
		status := http.StatusBadRequest
		if code == "too_many_operations" || code == "payload_too_large" {
			status = http.StatusRequestEntityTooLarge
		}
		jsonErrCode(w, status, code, message)
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer tx.Rollback()
	if code, message, err := validateScopedBlobReferences(tx, scope, req.Ops); err != nil {
		jsonInternalError(w, err)
		return
	} else if code != "" {
		jsonErrCode(w, http.StatusBadRequest, code, message)
		return
	}
	if req.IdempotencyKey != "" {
		var cachedJSON string
		err := tx.QueryRow(`SELECT response_json FROM server_idempotency_keys
			WHERE user_id=? AND vault_id=? AND idempotency_key=?`,
			scope.UserID, scope.VaultID, req.IdempotencyKey).Scan(&cachedJSON)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cachedJSON))
			return
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			jsonInternalError(w, err)
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var accepted []string
	var conflicts []map[string]interface{}
	for _, op := range req.Ops {
		if op.LastSeenServerSeq > 0 {
			conflictRows, err := tx.Query(`
				SELECT op_id, device_id, op_type, server_sequence FROM server_ops
				WHERE user_id=? AND vault_id=? AND entity_type=? AND entity_id=? AND device_id!=?
				  AND server_sequence > ? AND op_type != 'delete'
				ORDER BY server_sequence`, scope.UserID, scope.VaultID, op.EntityType, op.EntityID, scope.DeviceID, op.LastSeenServerSeq)
			if err != nil {
				jsonInternalError(w, err)
				return
			}
			for conflictRows.Next() {
				var cOpID, cDevID, cOpType string
				var cSeq int
				if err := conflictRows.Scan(&cOpID, &cDevID, &cOpType, &cSeq); err != nil {
					_ = conflictRows.Close()
					jsonInternalError(w, err)
					return
				}
				conflicts = append(conflicts, map[string]interface{}{
					"op_id":           cOpID,
					"device_id":       cDevID,
					"op_type":         cOpType,
					"server_sequence": cSeq,
					"entity_type":     op.EntityType,
					"entity_id":       op.EntityID,
				})
			}
			if err := conflictRows.Err(); err != nil {
				_ = conflictRows.Close()
				jsonInternalError(w, err)
				return
			}
			if err := conflictRows.Close(); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		res, err := tx.Exec(
			`INSERT OR IGNORE INTO server_ops (op_id, server_sequence, user_id, vault_id, device_id, entity_type, entity_id, op_type, payload_json, idempotency_key, client_sequence, last_seen_server_seq, created_at, pushed_at)
			 VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			op.OpID, scope.UserID, scope.VaultID, scope.DeviceID, op.EntityType, op.EntityID, op.OpType, op.PayloadJSON,
			req.IdempotencyKey, op.ClientSequence, op.LastSeenServerSeq, op.CreatedAt, now,
		)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		if n == 0 {
			continue
		}
		seqRes, err := tx.Exec("INSERT INTO server_revisions (op_id, device_id) VALUES (?, ?)", op.OpID, scope.DeviceID)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		seq, err := seqRes.LastInsertId()
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		if _, err := tx.Exec("UPDATE server_ops SET server_sequence=? WHERE op_id=?", seq, op.OpID); err != nil {
			jsonInternalError(w, err)
			return
		}
		if op.OpType == "delete" {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO server_tombstones
				(user_id, vault_id, entity_type, entity_id, op_id, deleted_at) VALUES (?, ?, ?, ?, ?, ?)`,
				scope.UserID, scope.VaultID, op.EntityType, op.EntityID, op.OpID, now); err != nil {
				jsonInternalError(w, err)
				return
			}
		}
		accepted = append(accepted, op.OpID)
	}
	resp := map[string]interface{}{
		"accepted":  accepted,
		"count":     len(accepted),
		"conflicts": conflicts,
	}
	if req.IdempotencyKey != "" {
		respJSON, err := json.Marshal(resp)
		if err != nil {
			jsonInternalError(w, err)
			return
		}
		if _, err := tx.Exec(`INSERT INTO server_idempotency_keys
			(user_id, vault_id, idempotency_key, response_json, created_at) VALUES (?, ?, ?, ?, ?)`,
			scope.UserID, scope.VaultID, req.IdempotencyKey, string(respJSON), now); err != nil {
			jsonInternalError(w, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, resp)
}

func (s *Server) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}
	scope, ok := s.requireSyncScope(w, r)
	if !ok {
		return
	}
	var req syncPullRequest
	if !decodeJSONBody(w, r, &req, s.cfg.Limits.MaxJSONBody) {
		return
	}
	if req.SinceSequence < 0 || req.PageLimit < 0 {
		jsonErrCode(w, http.StatusBadRequest, "invalid_request", "sequence and page_limit must be non-negative")
		return
	}
	pageLimit := s.pullPageLimit(req.PageLimit)
	var serverSeq int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(server_sequence), 0) FROM server_ops
		WHERE user_id=? AND vault_id=?`, scope.UserID, scope.VaultID).Scan(&serverSeq); err != nil {
		jsonInternalError(w, err)
		return
	}
	rows, err := s.db.Query(`
		SELECT op_id, server_sequence, device_id, entity_type, entity_id, op_type, payload_json, created_at
		FROM server_ops
		WHERE user_id=? AND vault_id=? AND server_sequence > ? AND server_sequence IS NOT NULL
		ORDER BY server_sequence LIMIT ?`, scope.UserID, scope.VaultID, req.SinceSequence, pageLimit+1)
	if err != nil {
		jsonInternalError(w, err)
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
	ops := make([]opDTO, 0, pageLimit)
	for rows.Next() {
		var o opDTO
		if err := rows.Scan(&o.OpID, &o.ServerSequence, &o.DeviceID, &o.EntityType, &o.EntityID, &o.OpType, &o.PayloadJSON, &o.CreatedAt); err != nil {
			jsonInternalError(w, err)
			return
		}
		ops = append(ops, o)
	}
	if err := rows.Err(); err != nil {
		jsonInternalError(w, err)
		return
	}
	hasMore := len(ops) > pageLimit
	if hasMore {
		ops = ops[:pageLimit]
	}
	pageLastSequence := req.SinceSequence
	if len(ops) > 0 {
		pageLastSequence = ops[len(ops)-1].ServerSequence
	}
	jsonOK(w, map[string]interface{}{
		"server_sequence":    serverSeq,
		"page_last_sequence": pageLastSequence,
		"has_more":           hasMore,
		"ops":                ops,
	})
}

func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireSyncScope(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case "POST":
		s.handleBlobUpload(w, r, scope)
	case "GET":
		shaHex := strings.TrimPrefix(r.URL.Path, "/api/v1/blobs/")
		s.handleBlobDownload(w, r, scope, shaHex)
	default:
		methodNotAllowed(w, "GET", "POST")
	}
}
