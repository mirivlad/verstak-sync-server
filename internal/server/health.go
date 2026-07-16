package server

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	Users          int    `json:"users"`
	ActiveDevices  int    `json:"active_devices"`
	RevokedDevices int    `json:"revoked_devices"`
	Vaults         int    `json:"vaults"`
	Operations     int    `json:"operations"`
	DatabaseBytes  int64  `json:"database_bytes"`
	BlobBytes      int64  `json:"blob_bytes"`
	LastSyncAt     string `json:"last_sync_activity"`
}

func (s *Server) Stats(ctx context.Context) (ServerStats, error) {
	var stats ServerStats
	queries := []struct {
		query  string
		target *int
	}{
		{"SELECT COUNT(*) FROM server_users", &stats.Users},
		{"SELECT COUNT(*) FROM server_devices WHERE COALESCE(revoked_at, '') = ''", &stats.ActiveDevices},
		{"SELECT COUNT(*) FROM server_devices WHERE COALESCE(revoked_at, '') != ''", &stats.RevokedDevices},
		{"SELECT COUNT(DISTINCT user_id || ':' || vault_id) FROM server_devices WHERE COALESCE(user_id,'') != '' AND COALESCE(vault_id,'') != ''", &stats.Vaults},
		{"SELECT COUNT(*) FROM server_ops", &stats.Operations},
	}
	for _, query := range queries {
		if err := s.db.QueryRowContext(ctx, query.query).Scan(query.target); err != nil {
			return ServerStats{}, err
		}
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
	return stats, nil
}
