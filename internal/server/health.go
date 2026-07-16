package server

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type HealthStatus struct {
	Status              string `json:"status"`
	Version             string `json:"version"`
	BuildCommit         string `json:"build_commit"`
	UptimeSeconds       int64  `json:"uptime_seconds"`
	DatabaseReachable   bool   `json:"database_reachable"`
	BlobStorageWritable bool   `json:"blob_storage_writable"`
	SchemaVersion       int    `json:"schema_version"`
	ServerTime          string `json:"server_time"`
}

func (s *Server) healthStatus(ctx context.Context) HealthStatus {
	health := HealthStatus{
		Status:        "ok",
		Version:       Version,
		BuildCommit:   BuildCommit,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		ServerTime:    time.Now().UTC().Format(time.RFC3339),
	}
	if s.db == nil || s.db.PingContext(ctx) != nil {
		health.DatabaseReachable = false
		health.Status = "degraded"
	} else {
		health.DatabaseReachable = true
		if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&health.SchemaVersion); err != nil {
			health.DatabaseReachable = false
			health.Status = "degraded"
		}
	}
	health.BlobStorageWritable = s.blobStorageWritable()
	if !health.BlobStorageWritable {
		health.Status = "degraded"
	}
	return health
}

func (s *Server) blobStorageWritable() bool {
	if s.blobsDir == "" {
		return false
	}
	probe, err := os.CreateTemp(s.blobsDir, ".health-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return false
	}
	return os.Remove(name) == nil
}

// ServerStats is intentionally independent from the web UI so a future
// admin panel can expose operational data without coupling to templates.
type ServerStats struct {
	Users            int    `json:"users"`
	ActiveUsers      int    `json:"active_users"`
	BlockedUsers     int    `json:"blocked_users"`
	UnconfirmedUsers int    `json:"unconfirmed_users"`
	ActiveDevices    int    `json:"active_devices"`
	RevokedDevices   int    `json:"revoked_devices"`
	Vaults           int    `json:"vaults"`
	Operations       int    `json:"operations"`
	Operations24h    int    `json:"operations_24h"`
	Blobs            int    `json:"blobs"`
	BlobReferences   int    `json:"blob_references"`
	OrphanBlobs      int    `json:"orphan_blobs"`
	TempUploads      int    `json:"temp_uploads"`
	ExpiredSessions  int    `json:"expired_sessions"`
	ExpiredTokens    int    `json:"expired_email_tokens"`
	AuditEvents      int    `json:"audit_events"`
	DatabaseBytes    int64  `json:"database_bytes"`
	BlobBytes        int64  `json:"blob_bytes"`
	LastSyncAt       string `json:"last_sync_activity"`
	LastCleanupAt    string `json:"last_cleanup_at"`
}

func (s *Server) Stats(ctx context.Context) (ServerStats, error) {
	var stats ServerStats
	now := time.Now().UTC()
	queries := []struct {
		query  string
		target *int
	}{
		{"SELECT COUNT(*) FROM server_users", &stats.Users},
		{"SELECT COUNT(*) FROM server_users WHERE confirmed=1 AND blocked=0", &stats.ActiveUsers},
		{"SELECT COUNT(*) FROM server_users WHERE blocked=1", &stats.BlockedUsers},
		{"SELECT COUNT(*) FROM server_users WHERE confirmed=0", &stats.UnconfirmedUsers},
		{"SELECT COUNT(*) FROM server_devices WHERE COALESCE(revoked_at, '') = ''", &stats.ActiveDevices},
		{"SELECT COUNT(*) FROM server_devices WHERE COALESCE(revoked_at, '') != ''", &stats.RevokedDevices},
		{"SELECT COUNT(DISTINCT user_id || ':' || vault_id) FROM server_devices WHERE COALESCE(user_id,'') != '' AND COALESCE(vault_id,'') != ''", &stats.Vaults},
		{"SELECT COUNT(*) FROM server_ops", &stats.Operations},
		{"SELECT COUNT(*) FROM server_blobs", &stats.Blobs},
		{"SELECT COUNT(*) FROM server_blob_refs", &stats.BlobReferences},
		{"SELECT COUNT(*) FROM server_blobs b WHERE NOT EXISTS (SELECT 1 FROM server_blob_refs r WHERE r.sha256=b.sha256)", &stats.OrphanBlobs},
		{"SELECT COUNT(*) FROM server_audit_log", &stats.AuditEvents},
	}
	for _, query := range queries {
		if err := s.db.QueryRowContext(ctx, query.query).Scan(query.target); err != nil {
			return ServerStats{}, err
		}
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM server_ops WHERE created_at >= ?", now.Add(-24*time.Hour).Format(time.RFC3339)).Scan(&stats.Operations24h); err != nil {
		return ServerStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM server_sessions WHERE expires_at <= ?", now.Format(time.RFC3339)).Scan(&stats.ExpiredSessions); err != nil {
		return ServerStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM server_email_tokens WHERE expires_at <= ?", now.Format(time.RFC3339)).Scan(&stats.ExpiredTokens); err != nil {
		return ServerStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(created_at),'') FROM server_audit_log WHERE event_type='retention_cleanup'").Scan(&stats.LastCleanupAt); err != nil {
		return ServerStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(last_seen), '') FROM server_devices").Scan(&stats.LastSyncAt); err != nil {
		return ServerStats{}, err
	}
	if info, err := os.Stat(s.dbPath); err == nil {
		stats.DatabaseBytes = info.Size()
	}
	if err := filepath.WalkDir(s.blobsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			stats.BlobBytes += info.Size()
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return ServerStats{}, fmt.Errorf("blob storage stats: %w", err)
	}
	if entries, err := os.ReadDir(s.blobsDir); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".upload-") {
				stats.TempUploads++
			}
		}
	} else if !os.IsNotExist(err) {
		return ServerStats{}, fmt.Errorf("temporary upload stats: %w", err)
	}
	return stats, nil
}
