# Verstak Sync Server

Standalone sync server for Verstak2 platform.

## Overview

This server provides synchronization between devices running Verstak2. It handles:

- Device registration and authentication
- Operational transform-based sync
- Blob storage for attachments
- User management with email confirmation

## Quick Start

```bash
# Build (produces binary at build/bin/verstak-sync-server)
./scripts/build.sh

# Run
./build/bin/verstak-sync-server --port 47732 --data ./server-data

# First run with admin user
./build/bin/verstak-sync-server --admin-user admin --admin-pass secret
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 47732 | HTTP port |
| `--data` | ./server-data | Data directory |
| `--admin-user` | | Create admin user (first run) |
| `--admin-pass` | | Admin password (first run) |

## Architecture

```
cmd/server/          - Entry point
internal/server/     - Server implementation
  - server.go        - Core server logic
  - handlers.go      - HTTP handlers
  - schema.go        - Database schema
```

## API Endpoints

- `POST /api/push` - Push operations to server
- `GET /api/pull` - Pull operations from server
- `POST /api/device/pair` - Pair device with token
- `POST /api/user/register` - Register new user
- `POST /api/user/login` - User login

## Development

```bash
# Run tests
go test ./...

# Build for production
CGO_ENABLED=1 go build -o verstak-sync-server ./cmd/server
```

## License

MIT
