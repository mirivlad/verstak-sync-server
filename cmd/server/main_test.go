package main

import (
	"strings"
	"testing"

	"github.com/verstak/verstak-sync-server/internal/server"
)

func TestBootstrapAdminFromEnv(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := server.LoadConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERSTAK_REQUIRE_ADMIN", "1")
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_PASSWORD", "")
	if err := bootstrapAdminFromEnv(cfg); err == nil {
		t.Fatal("first start without a password must fail")
	}
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_PASSWORD", "short")
	if err := bootstrapAdminFromEnv(cfg); err == nil {
		t.Fatal("short bootstrap password must fail")
	}
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_USER", "owner")
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_PASSWORD", "first-long-password")
	if err := bootstrapAdminFromEnv(cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.CheckAdmin("owner", "first-long-password") {
		t.Fatal("bootstrap credentials do not work")
	}
	if strings.Contains(cfg.Admin[0].PasswordHash, "first-long-password") {
		t.Fatal("admin password was stored in plaintext")
	}

	reloaded, err := server.LoadConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_PASSWORD", "second-long-password")
	if err := bootstrapAdminFromEnv(reloaded); err != nil {
		t.Fatal(err)
	}
	if !reloaded.CheckAdmin("owner", "first-long-password") || reloaded.CheckAdmin("owner", "second-long-password") {
		t.Fatal("restart must not reset the existing admin password")
	}
	t.Setenv("VERSTAK_BOOTSTRAP_ADMIN_PASSWORD", "")
	if err := bootstrapAdminFromEnv(reloaded); err != nil {
		t.Fatal("clearing the bootstrap variable must not block later starts:", err)
	}
}
