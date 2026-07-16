# Verstak Sync Server

Standalone sync server for Verstak2 platform.

## Overview

This server provides synchronization between devices running Verstak2. It handles:

- Device registration and authentication
- Vault-scoped, ordered operation-log relay with server sequence numbers
- Scoped content-addressed Blob transport for binary and large file content
- User management with email confirmation

## Quick Start

```bash
# Build (produces binary at build/bin/verstak-sync-server)
./scripts/build.sh

# Run
./build/bin/verstak-sync-server --data ./server-data

# First run with admin user
printf '%s\n' 'choose-a-long-password' > /tmp/verstak-admin-password
chmod 600 /tmp/verstak-admin-password
./build/bin/verstak-sync-server --admin-user admin --admin-pass-file /tmp/verstak-admin-password
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
| `--listen` | `127.0.0.1:47732` | HTTP address; an administrator must explicitly expose another interface |
| `--port` | — | Deprecated compatibility shortcut; always binds loopback |
| `--data` | ./server-data | Data directory |
| `--admin-user` | | Create admin user (first run) |
| `--admin-pass-file` | | Read the initial admin password from a protected file |
| `--admin-pass-stdin` | | Read the initial admin password from stdin |

The server has explicit header/read/write/idle timeouts and a 16 KiB header
limit. It handles SIGINT/SIGTERM with a 20-second graceful shutdown and closes
SQLite afterwards. Release builds publish `version` and `build_commit` through
the health response; neither logs nor health contain credentials.

`config.yml` can set `listen`, `public_url`, `trusted_proxies`, and limits:

```yaml
listen: 127.0.0.1:47732
public_url: https://sync.example.test
trusted_proxies: [127.0.0.1, ::1]
limits:
  max_json_body: 2097152
  max_push_operations: 100
  max_payload_json: 262144
  max_pull_page: 100
  max_blob_bytes: 268435456
  max_vault_blob_bytes: 4294967296
  max_user_blob_bytes: 8589934592
retention:
  idempotency_hours: 24
  audit_days: 90
  temp_upload_hours: 24
web:
  # Server default; visitors may choose System, Русский, or English in a cookie.
  default_locale: en
  # Set false for invite/admin-only installations.
  allow_registration: true
  # Product name rendered in the embedded web console.
  server_name: Verstak Sync Server
```

Production installs use:

- binary: `/opt/verstak-sync-server/verstak-sync-server`;
- data directory: `/var/lib/verstak-sync-server`;
- listen-address environment file: `/etc/verstak-server/env`;
- service: `verstak-server`.

Install from a built binary:

```bash
./scripts/build.sh
sudo ./scripts/install.sh \
  --bin ./build/bin/verstak-sync-server \
  --listen 127.0.0.1:47732 \
  --admin-user admin \
  --admin-pass-file /root/verstak-admin-password
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
echo 'VERSTAK_LISTEN=127.0.0.1:47733' | sudo tee /etc/verstak-server/env
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
curl http://127.0.0.1:47732/api/v1/health
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
- `GET /api/v1/auth/confirm?token=...` - Display a confirmation form; `POST` performs confirmation
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/forgot` - Request password reset
- `POST /api/v1/auth/reset` - Reset password
- `GET /api/v1/user/devices` - List devices for the current user session

Operational endpoints:

- `GET /api/v1/health` - Server health and basic storage status
- `/admin/...` - Admin web UI and admin JSON endpoints
- `/register`, `/login`, `/dashboard`, `/forgot`, `/reset`, `/logout` - User web UI

## Embedded web console

The server embeds its public, account, and administrator interface in the Go
binary. It has no CDN, npm build, external font, or remote analytics
dependency. `/` is a localized public page; `/login`, `/register`, `/forgot`,
and `/reset` use post/redirect/get flows. `/dashboard` lets a signed-in user
review their own devices and revoke one only after entering their password.

`/admin/login` opens the administrator console. Its sidebar provides overview,
users, devices, vaults, storage, audit, SMTP settings, and diagnostics. User
blocking is immediate; device revocation and SMTP changes require the current
administrator password again. Admin HTML is deliberately a normal server
rendered control plane; the existing `/admin/api/...` endpoints remain for
automation.

The locale resolver uses the `verstak_locale` HttpOnly/Lax cookie first. Its
values are `ru`, `en`, or `system`; `system` uses `Accept-Language`, then
`web.default_locale`, then English. The choice survives login and logout.
Registration is controlled by `web.allow_registration`; when disabled the
public registration page does not expose account creation.

All browser mutations use POST and validate a server-side session plus CSRF
token. The server returns security headers including a restrictive CSP,
`frame-ancestors 'none'`, `nosniff`, and a same-origin referrer policy. The
console must still be deployed behind the HTTPS reverse proxy described below:
secure cookies are enabled when HTTPS is detected through a trusted proxy.

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
workspace identity remain Desktop-core responsibilities. Small text can remain
inline; binary and large files are uploaded first and their operations carry a
`blob` `{sha256,size}` reference. Blob bytes are physically deduplicated but a
`user_id`/`vault_id` reference is mandatory. Knowing another scope's SHA-256
never grants download access. Revoked devices and blocked users lose sync and
blob access immediately.

`POST /api/v1/sync/pull` accepts `since_sequence` and optional `page_limit`.
The response has ordered `ops`, `page_last_sequence`, `server_sequence`, and
`has_more`. Clients must persist a cursor only after applying each operation.
Push is capped by the configured JSON/body/field limits and returns stable
JSON `{error,code}` errors (including `request_too_large`, `rate_limited`, and
`quota_exceeded`); desktop and UI localize codes rather than server text.

New device tokens, sessions, and email/reset tokens are stored only as SHA-256
hashes. The plaintext device token is returned once by pairing. Older plaintext
API keys are marked `legacy_api_key=1` during migration and are never created
again; rotate/re-pair them during normal deployment. Admin key endpoints show
only a prefix/suffix hint. Sessions are database-backed, expire after 24 hours,
rotate on login, and use HttpOnly/Lax cookies plus a SameSite/CSRF companion
cookie. Mutating browser endpoints require a matching CSRF token and do not use
GET for destructive work.

### Reverse proxy and TLS

TLS terminates at nginx or Caddy; the server has no built-in TLS. It ignores
`Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Proto` unless the TCP peer is
listed in `trusted_proxies`. For a local nginx/Caddy proxy use
`trusted_proxies: [127.0.0.1, ::1]` and set `public_url` to the HTTPS URL.

```nginx
location / {
  proxy_pass http://127.0.0.1:47732;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Never bind `0.0.0.0` merely to make a proxy work. If an external listener is
intentional, restrict it with a firewall and configure the real proxy CIDR.

### Operations, retention, and privacy

`GET /api/v1/health`, `/livez`, and `/readyz` report status, version, build,
uptime, database reachability, blob writability, schema version, and server
time without paths or secrets. The internal stats service exposes user/device,
vault, operation, database/blob size, and last-sync counters for a future
admin panel.

Retention cleans expired sessions/email tokens, bounded idempotency records,
old audit entries, stale upload temp files, and in-memory rate buckets. It does
**not** delete sync operations or referenced blobs: without a materialized
checkpoint and verified recovery protocol, pruning would prevent a new device
from restoring a vault. That checkpoint/operation-retention design is a future
milestone.

The server is optional: Desktop remains local-first. The relay can see metadata
and file bytes needed to serve operations/blobs; files are not end-to-end
encrypted in this milestone. Secrets, plugin settings, Todo, Journal,
Activity, and Browser Inbox are not synchronized here.

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
