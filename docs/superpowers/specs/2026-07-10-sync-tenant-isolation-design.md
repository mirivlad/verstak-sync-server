# Sync Tenant Isolation Design

**Status:** approved for implementation by the project owner on 2026-07-10.

## Goal

Make sync operations private to the authenticated user and vault, and make the
server, not the request body, the authority for the originating device.

## Scope

- Bind new desktop pairings to the current vault ID.
- Persist `user_id` and `vault_id` with every sync operation.
- Scope push conflict detection, pull cursors, tombstones, and idempotency
  responses to that pair of identifiers.
- Ignore the legacy `device_id` field in a push body for authorization and
  storage; retain it in the wire format for backward-compatible decoding.
- Upgrade existing SQLite databases without deleting data.

Blob ownership, API-key retirement, reset-token handling, HTML escaping, and
upload limits are separate security slices and are deliberately not included
in this change.

## Data model

`server_devices` gains a nullable `vault_id`. A device created through either
enrollment endpoint must have a non-empty vault ID that does not use the
reserved `legacy:` prefix. The authenticated device therefore identifies one
user and one vault.

`server_ops` gains `user_id` and `vault_id`. New writes always set both from
the authenticated device. Pull and conflict queries filter both fields.

`server_tombstones` is rebuilt with a composite key of
`(user_id, vault_id, entity_type, entity_id)`. `server_idempotency_keys` is
rebuilt with a composite key of `(user_id, vault_id, idempotency_key)`.

Existing devices without `vault_id` use the explicit effective scope
`legacy:<user_id>`. Existing operations inherit their device owner and that
legacy scope during startup migration. This preserves existing single-vault
accounts while preventing data from crossing account boundaries. New pairings
never use the legacy scope.

Desktop sync state, operation queues, cursors, and persisted device IDs are
vault-local. The desktop recreates its sync service whenever the active vault
is created, opened, or switched. When it opens a legacy vault state without a
stored device ID, it obtains the authenticated ID from `/api/client/me` before
syncing and persists it locally.

## API contract

`POST /api/client/pair` accepts a required `vault_id`. The desktop gets it
from `.verstak/vault.json` and sends it while pairing.

`POST /api/v1/sync/push` keeps accepting `device_id` for old clients, but the
server ignores it. The stored operation device ID is always the authenticated
device. A request whose token is not associated with a user and effective
vault returns a client error.

`POST /api/v1/sync/pull` returns only operations from the authenticated
user/vault scope. `server_sequence` is the highest sequence in that scope;
global sequence gaps are not exposed as the caller's cursor.

## Migration and failure handling

Startup migration is idempotent. It checks SQLite table columns before adding
new operation/device fields, backfills `user_id` from each operation's device,
and assigns the explicit legacy scope when an old device has no vault ID.
Tables whose primary key must change are rebuilt transactionally.

The prior global idempotency cache is intentionally discarded during migration:
it is only a replay cache and retaining it could replay one tenant's response
for another tenant.

If an operation cannot be associated with a user, it remains unscoped and is
not readable through sync APIs. The server must not guess an owner from a
request body.

## Verification

Focused server tests must prove:

1. two users cannot pull each other's operations;
2. two vaults of one user cannot pull each other's operations;
3. a caller cannot forge another device through the push body;
4. scoped idempotency does not replay another tenant's response;
5. a legacy SQLite database is upgraded with its existing operation retained
   in the matching legacy scope.
6. switching the active desktop vault rebinds the sync queue, cursor, and
   device identity to the new vault.

Desktop tests must prove that pairing sends the opened vault's persistent ID.
