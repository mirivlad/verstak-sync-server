# Sync Tenant Isolation Implementation Plan

> **For agentic workers:** execute this plan task by task with focused tests
> before each implementation change.

**Goal:** prevent cross-user and cross-vault operation visibility while binding
the persisted source device to the authenticated token.

**Architecture:** the server derives user, device, and vault scope from the
bearer token. SQLite rows carry that scope; desktop sends the immutable vault
ID only while creating a pairing. Existing unscoped devices and operations are
migrated into a deterministic legacy scope.

**Tech stack:** Go, `database/sql`, SQLite, `net/http`, desktop Go sync client.

## Task 1: Establish server behaviour tests

**Files:**
- Modify: `internal/server/server_test.go`

- [x] Add helpers that create confirmed users and token-authenticated devices
  with a specified vault ID.
- [x] Add a failing test where separate users push and pull from the same
  vault ID; each pull must contain only its own operation and cursor.
- [x] Add a failing test where one user owns devices in two vaults; pulls must
  remain vault-local.
- [x] Add a failing test that sends another device's ID in `push`; assert the
  stored and returned operation uses the authenticated device ID.
- [x] Add a failing test for identical idempotency keys in different scopes.
- [x] Run: `go test ./internal/server -run 'TestSync.*Isolation|TestSyncPush'`
  and confirm the new assertions fail for the intended missing behaviour.

## Task 2: Add idempotent SQLite scope migration

**Files:**
- Modify: `internal/server/schema.go`
- Modify: `internal/server/server.go`
- Test: `internal/server/server_test.go`

- [x] Define `vault_id` on new devices and `user_id`/`vault_id` on new
  operations; define scoped tombstone and idempotency primary keys.
- [x] Add startup migration helpers that inspect columns, add compatible
  columns, backfill owner IDs, assign `legacy:<user_id>` to old scopes, and
  rebuild the two tables whose primary keys change.
- [x] Add a failing legacy-schema fixture test, then make it pass by opening
  the database through `NewServer` and asserting its operation has the
  expected owner and legacy scope.
- [x] Run: `go test ./internal/server -run 'Test.*Migration|TestSync.*'`.

## Task 3: Apply authenticated scope to sync handlers

**Files:**
- Modify: `internal/server/middleware.go`
- Modify: `internal/server/handlers_api.go`
- Test: `internal/server/server_test.go`

- [x] Extend authenticated device lookup to provide the effective vault scope;
  missing user ownership must not authorize sync operations.
- [x] Require `vault_id` when creating a new client pairing and store it with
  the device.
- [x] Make push use authenticated device/user/vault values for inserts,
  conflicts, revisions, tombstones, and idempotency lookup/storage.
- [x] Make pull filter operations and its reported cursor by authenticated
  user/vault.
- [x] Run the focused tests from Task 1 until green, then
  `go test ./internal/server`.

## Task 4: Send the current vault ID while pairing

**Files:**
- Modify: `../verstak-desktop/internal/core/sync/client.go`
- Modify: `../verstak-desktop/internal/core/sync/client_test.go`
- Modify: `../verstak-desktop/internal/api/app.go`
- Modify: `../verstak-desktop/internal/api/app_test.go`

- [x] Add `vault_id` to the pair request and expose it in the pairing client
  method without changing push/pull wire compatibility.
- [x] Read the open vault metadata in `syncConfigure`; reject configuration if
  the vault ID is absent.
- [x] Add a failing client/API test that captures the pair request and asserts
  the persistent vault ID is sent.
- [x] Rebind desktop sync state, cursor, and persisted device identity whenever
  a vault is created, opened, or switched.
- [x] Hydrate missing legacy vault device IDs from the authenticated sync
  server before a token-based sync can use a global fallback.
- [x] Run: `go test ./internal/core/sync ./internal/api`.

## Task 5: Document, verify, and publish

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-07-10-sync-tenant-isolation-design.md`

- [x] Document that pairing is vault-bound and that sync cursors are scoped.
- [x] Run `gofmt` on all changed Go files.
- [x] Run `go test ./...` in both `verstak-sync-server` and
  `verstak-desktop`, then `git diff --check` in both repositories.
- [x] Commit and push the sync-server and desktop changes as coordinated
  security commits.
