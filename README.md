# Verstak Sync Server

Standalone sync server for Verstak2 platform.

## Overview

This server provides synchronization between devices running Verstak2. It handles:

- Device registration and authentication
- Vault-scoped, ordered operation-log relay with server sequence numbers
- Optional blob endpoints, not used by the current bounded Desktop file sync
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

## Release packages

Build a Linux amd64 archive locally:

```bash
./scripts/release.sh v0.1.0-alpha.1
```

It runs the server build and tests, then writes
`release/verstak-sync-server-linux-amd64-<version>.tar.gz` and `SHA256SUMS`.
The archive contains the server binary, systemd service file and install
script.

Publish those same assets to GitHub Releases:

```bash
./scripts/publish-github-release.sh v0.1.0-alpha.1
```

The publisher requires an authenticated [`gh`](https://cli.github.com/) CLI
and a clean local `main` equal to `origin/main`. It creates and pushes an
annotated tag when necessary, then creates or updates the GitHub Release.

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 47732 | HTTP port |
| `--data` | ./server-data | Data directory |
| `--admin-user` | | Create admin user (first run) |
| `--admin-pass` | | Admin password (first run) |

Production installs use:

- binary: `/opt/verstak-sync-server/verstak-sync-server`;
- data directory: `/var/lib/verstak-sync-server`;
- port environment file: `/etc/verstak-server/env`;
- service: `verstak-server`.

Install from a built binary:

```bash
./scripts/build.sh
sudo ./scripts/install.sh \
  --bin ./build/bin/verstak-sync-server \
  --port 47732 \
  --admin-user admin \
  --admin-pass 'change-this-password'
```

The install script creates a locked-down system user, initializes the data
directory, writes `/etc/verstak-server/env`, installs the systemd unit, and
starts the service.

## Deployment

Run the service behind HTTPS in production. The sync server itself listens on
plain HTTP; terminate TLS in a reverse proxy such as nginx, Caddy, or a platform
load balancer, then forward to `127.0.0.1:47732`.

Basic service operations:

```bash
sudo systemctl status verstak-server
sudo journalctl -u verstak-server -f
curl http://127.0.0.1:47732/api/v1/health
```

Change the listen port:

```bash
echo 'VERSTAK_PORT=47733' | sudo tee /etc/verstak-server/env
sudo systemctl restart verstak-server
```

Upgrade the binary:

```bash
./scripts/build.sh
sudo systemctl stop verstak-server
sudo install -m 755 ./build/bin/verstak-sync-server /opt/verstak-sync-server/verstak-sync-server
sudo systemctl start verstak-server
```

Keep `--data` stable across upgrades. The data directory is the durable relay
log for connected devices; each Desktop vault remains the source of truth for
its local-first files and workspace state.

## Backup And Restore

Back up the full data directory while the service is stopped. It contains:

- `server.db` - SQLite database with users, devices, operations, SMTP settings,
  and blob metadata;
- `config.yml` - admin user configuration;
- `blobs/` - content-addressed blob files.

Create a backup:

```bash
sudo systemctl stop verstak-server
sudo tar --xattrs --acls -czf verstak-sync-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  -C /var/lib verstak-sync-server
sudo systemctl start verstak-server
```

Restore onto a fresh host or after data loss:

```bash
sudo systemctl stop verstak-server
sudo mv /var/lib/verstak-sync-server /var/lib/verstak-sync-server.broken.$(date +%Y%m%d-%H%M%S) 2>/dev/null || true
sudo tar --xattrs --acls -xzf verstak-sync-backup-YYYYMMDD-HHMMSS.tar.gz -C /var/lib
sudo chown -R verstak:verstak /var/lib/verstak-sync-server
sudo chmod 750 /var/lib/verstak-sync-server
sudo systemctl start verstak-server
curl http://127.0.0.1:${VERSTAK_PORT:-47732}/api/v1/health
```

After restore, connected desktop clients keep their existing device tokens.
If a backup is older than some client changes, those clients may need to run
sync again so unpushed local operations are re-sent.

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

- `POST /api/client/pair` - Pair a desktop client with username/password and its persistent `vault_id`, then return a device token
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
`payload_json`, `device_id`, and sequencing metadata. A pairing token is bound
to one user and vault. The server derives the stored device ID and operation
scope from that token, ignores a caller-supplied `device_id` for authorization,
and returns only operations and cursors from the authenticated user/vault.
Operations are returned in increasing `server_sequence`; clients must stop at
the first operation they cannot apply and retry that sequence later. The server
does not merge files, resolve conflicts, or create replacement names.

The desktop pairing payload may supply an existing `vault_id` to add a new
empty local vault to that remote scope. The server treats that value only as a
scope selector: reconciliation, conflict detection, snapshots, and durable
workspace identity remain Desktop-core responsibilities. Current Desktop core
uses bounded inline file payloads (text or base64 up to 8 MB) and workspace
operations (`create`, `rename`, `trash`, `restore`). Blob transport, quotas,
pull pagination, and operation retention are a later milestone; the existing
blob endpoints must not be interpreted as enabled Desktop large-file sync.

New device enrollment requires a non-empty `vault_id`. The `legacy:` prefix is
reserved for server-side migration of older records and cannot be selected by
new clients.

## Development

```bash
# Run tests
go test ./...

# Build for production
CGO_ENABLED=1 go build -o verstak-sync-server ./cmd/server
```

## License

Copyright © 2026 Verstak contributors. Licensed under
[GNU AGPLv3 or later](LICENSE).
