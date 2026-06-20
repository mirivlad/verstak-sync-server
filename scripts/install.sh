#!/bin/sh
#
# install.sh — установка Verstak Sync Server
#
# Использование:
#   sudo ./install.sh --port 47732 --user verstak --admin-user admin --admin-pass secret
#
# Флаги:
#   --port         Порт сервера (по умолчанию: 47732)
#   --user         Системный пользователь (по умолчанию: verstak)
#   --admin-user   Логин администратора (обязательный)
#   --admin-pass   Пароль администратора (обязательный)
#   --bin          Путь к бинарнику (по умолчанию: ./verstak-sync-server)
#

set -e

# Defaults
PORT="${VERSTAK_PORT:-47732}"
USER="verstak"
ADMIN_USER=""
ADMIN_PASS=""
BIN="./verstak-sync-server"

# Parse flags
while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --admin-pass) ADMIN_PASS="$2"; shift 2 ;;
        --bin) BIN="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

if [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PASS" ]; then
    echo "Usage: $0 --admin-user USER --admin-pass PASS [--port PORT] [--user USER]"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)."
    exit 1
fi

echo "=== Verstak Sync Server Installation ==="
echo "Port:        $PORT"
echo "User:        $USER"
echo "Admin:       $ADMIN_USER"
echo "Binary:      $BIN"
echo ""

# 1. Create system user if not exists.
if ! id -u "$USER" >/dev/null 2>&1; then
    echo "Creating user: $USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# 2. Install binary.
INSTALL_DIR="/opt/verstak-sync-server"
if [ ! -f "$BIN" ]; then
    echo "Binary not found: $BIN. Build it first: go build -o $BIN ./cmd/server/"
    exit 1
fi
echo "Installing binary to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$BIN" "$INSTALL_DIR/verstak-sync-server"
chmod 755 "$INSTALL_DIR/verstak-sync-server"

# 3. Create data directory.
DATA_DIR="/var/lib/verstak-sync-server"
echo "Creating $DATA_DIR"
mkdir -p "$DATA_DIR"
chown "$USER:$USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

# 4. Set up admin user (first run).
echo "Setting up admin user"
"$INSTALL_DIR/verstak-sync-server" \
    --port "$PORT" \
    --data "$DATA_DIR" \
    --admin-user "$ADMIN_USER" \
    --admin-pass "$ADMIN_PASS" &
SERVER_PID=$!
sleep 2
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# 5. Install systemd unit.
echo "Installing systemd unit"
SERVICE_FILE="/etc/systemd/system/verstak-server.service"
cp "$(dirname "$0")/../verstak-server.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

# Set port in environment file.
mkdir -p /etc/verstak-server
echo "VERSTAK_PORT=$PORT" > /etc/verstak-server/env

# 6. Enable and start.
echo "Enabling and starting service"
systemctl daemon-reload
systemctl enable verstak-server
systemctl start verstak-server

echo ""
echo "=== Installation complete ==="
echo "Service: verstak-server"
echo "Port:    $PORT"
echo "Admin:   http://localhost:$PORT/admin/login"
echo ""
echo "Check status: systemctl status verstak-server"
echo "View logs:    journalctl -u verstak-server -f"
