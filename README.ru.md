<div align="center">

# Verstak Sync Server

### Собственный сервер синхронизации для vault-хранилищ Верстака.

[English](README.md) · **Русский**

[![Релиз](https://img.shields.io/github/v/release/mirivlad/verstak-sync-server?include_prereleases\&label=release)](https://github.com/mirivlad/verstak-sync-server/releases)
![Статус](https://img.shields.io/badge/status-alpha-orange)
[![Лицензия](https://img.shields.io/github/license/mirivlad/verstak-sync-server)](LICENSE)

</div>

> **Alpha-версия.** Сервер синхронизации дополняет локальный рабочий процесс.
> Desktop-приложение остаётся основным источником данных.

## Обзор

Сервер синхронизации обеспечивает обмен данными между устройствами с Verstak Desktop:

- Регистрация устройств и аутентификация
- Упорядоченный журнал операций с серверными номерами последовательности
- Передача бинарных и больших файлов через Blob API
- Управление пользователями с подтверждением email
- Встроенная веб-консоль для администратора и пользователей

## Быстрый старт

```bash
# Сборка
./scripts/build.sh

# Запуск
./build/bin/verstak-sync-server --data ./server-data

# Первый запуск с администратором
printf '%s\n' 'выберите-длинный-пароль' > /tmp/verstak-admin-password
chmod 600 /tmp/verstak-admin-password
./build/bin/verstak-sync-server --admin-user admin --admin-pass-file /tmp/verstak-admin-password
```

## Установка

Соберите бинарник и запустите установочный скрипт:

```bash
./scripts/build.sh
sudo ./scripts/install.sh \
  --bin ./build/bin/verstak-sync-server \
  --listen 127.0.0.1:47732 \
  --admin-user admin \
  --admin-pass-file /root/verstak-admin-password
```

Скрипт создаёт системного пользователя, инициализирует каталог данных и
устанавливает systemd-сервис `verstak-server`.

Основные операции:

```bash
sudo systemctl status verstak-server
sudo journalctl -u verstak-server -f
curl http://127.0.0.1:47732/api/v1/health
```

## Развёртывание

В production сервер должен работать за HTTPS. Сам сервер слушает plain HTTP;
TLS терминируется в обратном прокси (nginx, Caddy).

Пример nginx:

```nginx
location / {
  proxy_pass http://127.0.0.1:47732;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Всегда привязывайте сервер к loopback (`127.0.0.1`), если явно не нужен внешний
доступ.

## Резервное копирование и восстановление

Создание резервной копии (сервис должен быть остановлен):

```bash
sudo systemctl stop verstak-server
sudo tar --xattrs --acls -czf verstak-sync-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  -C /var/lib verstak-sync-server
sudo systemctl start verstak-server
```

Восстановление:

```bash
sudo systemctl stop verstak-server
sudo tar --xattrs --acls -xzf verstak-sync-backup-ГГГГММДД-ЧЧММСС.tar.gz -C /var/lib
sudo chown -R verstak:verstak /var/lib/verstak-sync-server
sudo systemctl start verstak-server
```

## API

Desktop sync client:

| Метод | Назначение |
|-------|------------|
| `POST /api/client/pair` | Сопряжение устройства |
| `POST /api/auth/test` | Проверка учётных данных |
| `GET /api/client/me` | Информация о текущем устройстве |
| `POST /api/v1/sync/push` | Отправка локальных операций |
| `POST /api/v1/sync/pull` | Получение операций с сервера |
| `POST /api/v1/blobs/` | Загрузка бинарного файла |
| `GET /api/v1/blobs/{sha256}` | Скачивание бинарного файла |

User API:

| Метод | Назначение |
|-------|------------|
| `POST /api/v1/auth/register` | Регистрация |
| `POST /api/v1/auth/login` | Вход |
| `GET /api/v1/user/devices` | Список устройств |

Операционные:

| Метод | Назначение |
|-------|------------|
| `GET /api/v1/health` | Состояние сервера |

Административная веб-консоль доступна по `/admin/login`.

## Встроенная веб-консоль

Сервер включает встроенную веб-консоль без внешних зависимостей:

- Локализованные публичные страницы (System / English / Русский)
- Личный кабинет пользователя: устройства, подтверждение email
- Административная панель: пользователи, устройства, vaults, хранилище,
  аудит, SMTP, диагностика
- Защита сессиями, CSRF-токенами и security-заголовками

## Архитектура

Сервер не является источником истины для данных. Desktop остаётся local-first.
Сервер передаёт операции и blob-файлы между устройствами, но не сливает
содержимое файлов, не разрешает конфликты и не создаёт замещающих имён.

Файлы не имеют сквозного шифрования в текущем milestone. Секреты, настройки
плагинов, задачи, журнал, активность и браузерный inbox не синхронизируются.

## Лицензия

Copyright © 2026 Verstak contributors. Распространяется на условиях
[GNU AGPLv3 или новее](LICENSE).
