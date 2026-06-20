package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/verstak/verstak-sync-server/internal/server"
)

func main() {
	port := flag.Int("port", 47732, "HTTP port")
	dataDir := flag.String("data", "./server-data", "Data directory (db, blobs, config)")
	adminUser := flag.String("admin-user", "", "Create admin user (first run)")
	adminPass := flag.String("admin-pass", "", "Admin password (first run)")
	flag.Parse()

	absData, err := filepath.Abs(*dataDir)
	if err != nil {
		log.Fatalf("data dir: %v", err)
	}

	if err := os.MkdirAll(absData, 0750); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	cfg, err := server.LoadConfig(absData)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *adminUser != "" && *adminPass != "" {
		if err := cfg.SetAdmin(*adminUser, *adminPass); err != nil {
			log.Fatalf("set admin: %v", err)
		}
		fmt.Printf("Admin user %q created.\n", *adminUser)
	}

	dbPath := filepath.Join(absData, "server.db")
	srv, err := server.NewServer(dbPath, absData, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	defer srv.Close()

	srv.SetupRoutes()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Verstak Sync Server starting on %s (data: %s)", addr, absData)
	if err := srv.ListenAndServe(addr); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
