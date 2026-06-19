package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	// First-run admin setup.
	if *adminUser != "" && *adminPass != "" {
		fmt.Printf("Admin user %q created.\n", *adminUser)
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Verstak Sync Server starting on %s (data: %s)", addr, absData)
	log.Fatal(fmt.Errorf("server not yet implemented"))
}
