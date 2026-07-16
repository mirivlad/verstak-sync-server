package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/verstak/verstak-sync-server/internal/server"
)

func main() {
	dataDir := flag.String("data", "./server-data", "Data directory (db, blobs, config)")
	listen := flag.String("listen", "", "HTTP listen address (default 127.0.0.1:47732)")
	port := flag.Int("port", 0, "Deprecated compatibility override for the loopback port")
	adminUser := flag.String("admin-user", "", "Create admin user (first run)")
	adminPassFile := flag.String("admin-pass-file", "", "Read initial admin password from a 0600 file")
	adminPassStdin := flag.Bool("admin-pass-stdin", false, "Read initial admin password from stdin")
	showVersion := flag.Bool("version", false, "Print build version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("verstak-sync-server %s (%s)\n", server.Version, server.BuildCommit)
		return
	}

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

	if envListen := strings.TrimSpace(os.Getenv("VERSTAK_LISTEN")); envListen != "" {
		cfg.Listen = envListen
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *port != 0 && *listen == "" {
		cfg.Listen = fmt.Sprintf("127.0.0.1:%d", *port)
	}
	if publicURL := strings.TrimSpace(os.Getenv("VERSTAK_PUBLIC_URL")); publicURL != "" {
		cfg.PublicURL = publicURL
	}
	if trusted := strings.TrimSpace(os.Getenv("VERSTAK_TRUSTED_PROXIES")); trusted != "" {
		cfg.TrustedProxies = strings.Split(trusted, ",")
	}
	if err := cfg.Normalize(); err != nil {
		log.Fatalf("config: %v", err)
	}

	adminPass, err := initialAdminPassword(*adminPassFile, *adminPassStdin)
	if err != nil {
		log.Fatalf("admin password: %v", err)
	}
	if (*adminUser == "") != (adminPass == "") {
		log.Fatal("admin-user and one admin password source must be supplied together")
	}
	if *adminUser != "" {
		if err := cfg.SetAdmin(*adminUser, adminPass); err != nil {
			log.Fatalf("set admin: %v", err)
		}
		log.Printf("initial admin user %q configured", *adminUser)
	}

	dbPath := filepath.Join(absData, "server.db")
	srv, err := server.NewServer(dbPath, absData, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	srv.SetupRoutes()
	if err := srv.CleanupRetention(time.Now().UTC()); err != nil {
		_ = srv.Close()
		log.Fatalf("retention cleanup: %v", err)
	}
	addr := cfg.ListenAddress()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = srv.Close()
		log.Fatalf("listen %s: %v", addr, err)
	}
	httpServer := srv.HTTPServer(addr)
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	log.Printf("Verstak Sync Server %s (%s) listening on %s", server.Version, server.BuildCommit, addr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.Printf("received %s; shutting down", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = httpServer.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			log.Printf("graceful shutdown: %v", err)
		}
	case err = <-serveDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = srv.Close()
			log.Fatalf("serve: %v", err)
		}
	}
	if err := srv.Close(); err != nil {
		log.Printf("close database: %v", err)
	}
}

func initialAdminPassword(path string, useStdin bool) (string, error) {
	if path != "" && useStdin {
		return "", fmt.Errorf("choose either --admin-pass-file or --admin-pass-stdin")
	}
	if path == "" && !useStdin {
		return "", nil
	}
	var data []byte
	var err error
	if path != "" {
		data, err = os.ReadFile(path)
	} else {
		data, err = os.ReadFile("/dev/stdin")
	}
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(data))
	if password == "" {
		return "", fmt.Errorf("password source is empty")
	}
	return password, nil
}
