# Verstak Sync Server

Standalone sync server for Verstak2 platform.

## Overview

This server provides synchronization between devices running Verstak2. It handles:

- Device registration and authentication
- Operation log sync with server sequence numbers and conflict detection
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
  - routes.go        - HTTP routing
  - handlers_api.go  - Sync, client, health, and blob handlers
  - handlers_auth.go - User auth API handlers
  - handlers_admin.go - Admin web/API handlers
  - schema.go        - Database schema
```

## API Endpoints

Desktop sync client:

- `POST /api/client/pair` - Pair a desktop client with username/password and return a device token
- `POST /api/auth/test` - Validate username/password from the desktop client
- `GET /api/client/me` - Return current authenticated client/device details
- `POST /api/client/revoke-current` - Revoke the current desktop device token
- `POST /api/client/revoke-device` - Revoke another device owned by the same user
- `POST /api/v1/sync/push` - Push local operations to the server operation log
- `POST /api/v1/sync/pull` - Pull operations since a server sequence number
- `POST /api/v1/blobs/` - Store a multipart `file` blob and return its SHA-256 hash
- `GET /api/v1/blobs/{sha256}` - Download a stored blob by SHA-256 hash

User API:

- `POST /api/v1/auth/register` - Register a user
- `GET /api/v1/auth/confirm?token=...` - Confirm email
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/forgot` - Request password reset
- `POST /api/v1/auth/reset` - Reset password
- `GET /api/v1/user/devices` - List devices for the current user session

Operational endpoints:

- `GET /api/v1/health` - Server health and basic storage status
- `/admin/...` - Admin web UI and admin JSON endpoints
- `/register`, `/login`, `/dashboard`, `/forgot`, `/reset`, `/logout` - User web UI

Sync operations are generic records with `entity_type`, `entity_id`, `op_type`,
`payload_json`, `device_id`, and sequencing metadata. The server stores and
orders operations; Verstak desktop owns the v2 payload semantics.

## Development

```bash
# Run tests
go test ./...

# Build for production
CGO_ENABLED=1 go build -o verstak-sync-server ./cmd/server
```

## License

MIT
