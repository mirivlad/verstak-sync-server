package server

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CleanupRetention only removes independently expiring data. It intentionally
// never prunes server_ops or content-addressed blobs: the operation log remains
// required for a newly paired device until a future checkpoint protocol exists.
func (s *Server) CleanupRetention(now time.Time) error {
	if err := s.cleanupExpiredSessions(); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM server_email_tokens WHERE expires_at <= ?", now.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM server_idempotency_keys WHERE created_at < ?", now.Add(-time.Duration(s.cfg.Retention.IdempotencyHours)*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM server_audit_log WHERE created_at < ?", now.AddDate(0, 0, -s.cfg.Retention.AuditDays).UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.blobsDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".upload-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().Before(now.Add(-time.Duration(s.cfg.Retention.TempUploadHours) * time.Hour)) {
			if err := os.Remove(filepath.Join(s.blobsDir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
