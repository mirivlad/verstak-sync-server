# AGENTS.md — Verstak Sync Server

## Назначение

Отдельный сервер синхронизации для Верстака. Обеспечивает синхронизацию vault между устройствами.

## Правила

- Sync server не импортирует desktop UI или official plugins.
- Sync server синхронизирует vault metadata, файлы/blobs, plugin state (где разрешено).
- Плагины явно указывают, какие данные можно синхронизировать.
- Sync — не источник правды, а дополнение.

## API

```
POST   /api/v1/pair          — создание пары устройство-сервер
POST   /api/v1/auth           — аутентификация
GET    /api/v1/devices         — список устройств
POST   /api/v1/sync           — синхронизация операций
GET    /api/v1/blob/:hash     — скачать blob
PUT    /api/v1/blob/:hash     — загрузить blob
GET    /api/v1/operations     — получить операции с последнего sync point
```

## Структура

```
verstak-sync-server/
  AGENTS.md
  cmd/
    server/
  internal/
    api/
    auth/
    device/
    vault/
    blob/
    conflict/
  migrations/
    ...
  go.mod
  README.md
```
