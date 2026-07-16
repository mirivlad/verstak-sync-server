package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func blobPath(root, hash string) string {
	return filepath.Join(root, hash[:2], hash[2:4], hash)
}

func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request, scope authenticatedDevice) {
	// Reserve a little multipart framing headroom while the file itself is
	// measured independently. The stream is never materialized in memory.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxBlobBytes+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		jsonErrCode(w, http.StatusBadRequest, "invalid_multipart", "invalid multipart request")
		return
	}
	part, err := reader.NextPart()
	if errors.Is(err, io.EOF) {
		jsonErrCode(w, http.StatusBadRequest, "invalid_multipart", "file field is required")
		return
	}
	if err != nil {
		jsonErrCode(w, http.StatusBadRequest, "invalid_multipart", "invalid multipart request")
		return
	}
	defer part.Close()
	if part.FormName() != "file" || part.FileName() == "" {
		jsonErrCode(w, http.StatusBadRequest, "invalid_multipart", "exactly one file field is required")
		return
	}
	tmp, err := os.CreateTemp(s.blobsDir, ".upload-*")
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		jsonInternalError(w, err)
		return
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(part, s.cfg.Limits.MaxBlobBytes+1))
	if err != nil {
		_ = tmp.Close()
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonErrCode(w, http.StatusRequestEntityTooLarge, "blob_too_large", "blob is too large")
		} else {
			jsonInternalError(w, err)
		}
		return
	}
	if written > s.cfg.Limits.MaxBlobBytes {
		_ = tmp.Close()
		jsonErrCode(w, http.StatusRequestEntityTooLarge, "blob_too_large", "blob is too large")
		return
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		jsonInternalError(w, err)
		return
	}
	if err := tmp.Close(); err != nil {
		jsonInternalError(w, err)
		return
	}
	// Do not silently accept a second part: this endpoint has one unambiguous
	// file contract and no form fields that could hide extra request data.
	if extra, err := reader.NextPart(); err != io.EOF {
		if extra != nil {
			_ = extra.Close()
		}
		jsonErrCode(w, http.StatusBadRequest, "invalid_multipart", "exactly one file field is required")
		return
	}
	sha := hex.EncodeToString(hash.Sum(nil))
	if err := s.attachBlob(scope.UserID, scope.VaultID, sha, written, tmpName); err != nil {
		if errors.Is(err, errBlobTooLarge) {
			jsonErrCode(w, http.StatusRequestEntityTooLarge, "quota_exceeded", "blob quota exceeded")
			return
		}
		jsonInternalError(w, err)
		return
	}
	jsonOK(w, map[string]interface{}{"sha256": sha, "size": written})
}

var errBlobTooLarge = errors.New("blob quota exceeded")

// attachBlob checks logical quotas before the rename, then atomically makes
// the content reachable and commits the scope reference. A DB error removes a
// newly-created physical file so rejected requests leave no blob behind.
func (s *Server) attachBlob(userID, vaultID, sha string, size int64, tmpName string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingSize int64
	err = tx.QueryRow(`SELECT size FROM server_blob_refs WHERE user_id=? AND vault_id=? AND sha256=?`, userID, vaultID, sha).Scan(&existingSize)
	if err == nil {
		if existingSize != size {
			return fmt.Errorf("existing blob reference has a different size")
		}
		if _, err := tx.Exec(`UPDATE server_blob_refs SET last_accessed=? WHERE user_id=? AND vault_id=? AND sha256=?`, time.Now().UTC().Format(time.RFC3339), userID, vaultID, sha); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var vaultUsed, userUsed int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM server_blob_refs WHERE user_id=? AND vault_id=?`, userID, vaultID).Scan(&vaultUsed); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM server_blob_refs WHERE user_id=?`, userID).Scan(&userUsed); err != nil {
		return err
	}
	if vaultUsed+size > s.cfg.Limits.MaxVaultBlobBytes || userUsed+size > s.cfg.Limits.MaxUserBlobBytes {
		return errBlobTooLarge
	}
	destination := blobPath(s.blobsDir, sha)
	if err := os.MkdirAll(filepath.Dir(destination), 0750); err != nil {
		return err
	}
	createdPhysical := false
	if _, err := os.Stat(destination); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(tmpName, destination); err != nil {
			return err
		}
		createdPhysical = true
	} else if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`INSERT OR IGNORE INTO server_blobs (sha256, size, created_at) VALUES (?, ?, ?)`, sha, size, now); err != nil {
		if createdPhysical {
			_ = os.Remove(destination)
		}
		return err
	}
	if _, err := tx.Exec(`INSERT INTO server_blob_refs (user_id, vault_id, sha256, size, created_at, last_accessed) VALUES (?, ?, ?, ?, ?, ?)`, userID, vaultID, sha, size, now, now); err != nil {
		if createdPhysical {
			_ = os.Remove(destination)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		if createdPhysical {
			_ = os.Remove(destination)
		}
		return err
	}
	return nil
}

func (s *Server) handleBlobDownload(w http.ResponseWriter, r *http.Request, scope authenticatedDevice, sha string) {
	if !validSHA256(sha) {
		jsonErrCode(w, http.StatusBadRequest, "invalid_blob_hash", "invalid SHA-256")
		return
	}
	var size int64
	err := s.db.QueryRow(`SELECT size FROM server_blob_refs WHERE user_id=? AND vault_id=? AND sha256=?`, scope.UserID, scope.VaultID, sha).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		jsonErrCode(w, http.StatusNotFound, "blob_not_found", "blob not found")
		return
	}
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	file, err := os.Open(blobPath(s.blobsDir, sha))
	if errors.Is(err, os.ErrNotExist) {
		jsonErrCode(w, http.StatusNotFound, "blob_not_found", "blob not found")
		return
	}
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		jsonInternalError(w, err)
		return
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		jsonErrCode(w, http.StatusInternalServerError, "blob_unavailable", "blob is unavailable")
		return
	}
	if _, err := s.db.Exec(`UPDATE server_blob_refs SET last_accessed=? WHERE user_id=? AND vault_id=? AND sha256=?`, time.Now().UTC().Format(time.RFC3339), scope.UserID, scope.VaultID, sha); err != nil {
		jsonInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sha+"\"")
	// ServeContent streams from the file and provides safe Range support.
	http.ServeContent(w, r, sha, info.ModTime(), file)
}

// validateScopedBlobReferences ensures an accepted operation can later be
// restored by every authorized device in this scope. Legacy base64 binary
// payloads are deliberately rejected: binary content belongs in Blob storage,
// never in the operation log.
func validateScopedBlobReferences(tx *sql.Tx, scope authenticatedDevice, ops []syncPushOperation) (code, message string, err error) {
	for _, op := range ops {
		if op.EntityType != "file" || op.PayloadJSON == "" {
			continue
		}
		var payload struct {
			DataBase64 *string `json:"dataBase64"`
			Blob       *struct {
				SHA256 string `json:"sha256"`
				Size   int64  `json:"size"`
			} `json:"blob"`
		}
		if err := json.Unmarshal([]byte(op.PayloadJSON), &payload); err != nil {
			return "invalid_payload", "operation payload_json must be valid JSON", nil
		}
		if payload.DataBase64 != nil {
			return "inline_binary_forbidden", "binary file payload must reference a blob", nil
		}
		if payload.Blob == nil {
			continue
		}
		if !validSHA256(payload.Blob.SHA256) || payload.Blob.Size < 0 {
			return "invalid_blob_reference", "invalid blob reference", nil
		}
		var storedSize int64
		err := tx.QueryRow(`SELECT size FROM server_blob_refs WHERE user_id=? AND vault_id=? AND sha256=?`,
			scope.UserID, scope.VaultID, payload.Blob.SHA256).Scan(&storedSize)
		if errors.Is(err, sql.ErrNoRows) {
			return "blob_not_owned", "blob must be uploaded before its operation", nil
		}
		if err != nil {
			return "", "", err
		}
		if storedSize != payload.Blob.Size {
			return "invalid_blob_reference", "blob size does not match uploaded content", nil
		}
	}
	return "", "", nil
}
