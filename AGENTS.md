# AGENTS.md — Verstak Sync Server

## Назначение

Отдельный сервер синхронизации для Верстака. Обеспечивает синхронизацию vault между устройствами.

## Правила

- Sync server не импортирует desktop UI или official plugins.
- Sync server синхронизирует vault metadata, файлы/blobs, plugin state (где разрешено).
- Плагины явно указывают, какие данные можно синхронизировать.
- Sync — не источник правды, а дополнение.

## API (текущий)

Desktop sync client:

```
POST   /api/client/pair              — pair device with username/password
POST   /api/auth/test                — validate username/password
GET    /api/client/me                 — current authenticated device details
POST   /api/client/revoke-current     — revoke current device token
POST   /api/client/revoke-device      — revoke another device
POST   /api/v1/sync/push              — push local operations
POST   /api/v1/sync/pull              — pull operations since server sequence
POST   /api/v1/blobs/                 — store a blob, return SHA-256
GET    /api/v1/blobs/{sha256}         — download a stored blob
```

User API:

```
POST   /api/v1/auth/register          — register a user
GET    /api/v1/auth/confirm           — confirm email (GET shows form, POST confirms)
POST   /api/v1/auth/login             — user login
POST   /api/v1/auth/forgot            — request password reset
POST   /api/v1/auth/reset             — reset password
GET    /api/v1/user/devices           — list user devices
```

Operational:

```
GET    /api/v1/health                 — server health and storage status
GET    /livez                         — liveness probe
GET    /readyz                        — readiness probe
```

Embedded web console:

```
GET    /                              — public page
GET    /login, /register, /forgot, /reset, /logout
GET    /dashboard                     — user device management
GET    /admin/login                   — admin console
GET    /admin/...                     — admin sections (users, devices, vaults, storage, audit, SMTP, diagnostics)
```

## Структура

```
verstak-sync-server/
  AGENTS.md
  cmd/
    server/
  internal/
    server/
      server.go
      routes.go
      handlers_api.go
      handlers_auth.go
      handlers_admin.go
      schema.go
    web/
      ...
  go.mod
  README.md
```

## Подробнее

См. [README.md](README.md) для полной документации по развёртыванию,
конфигурации, backup/restore и архитектуре.
