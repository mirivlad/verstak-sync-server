package server

import (
	"os"
	"path/filepath"
	"testing"
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
