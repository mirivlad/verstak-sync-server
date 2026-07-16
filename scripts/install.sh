#!/bin/sh
# Install a locally built Verstak Sync Server without exposing an admin
# password through argv or the installation log.
set -eu
umask 077

LISTEN="${VERSTAK_LISTEN:-127.0.0.1:47732}"
USER="verstak"
ADMIN_USER=""
ADMIN_PASS_FILE=""
BIN="./verstak-sync-server"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --listen) LISTEN="$2"; shift 2 ;;
        --port) LISTEN="127.0.0.1:$2"; shift 2 ;; # compatibility, still loopback
        --user) USER="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --admin-pass-file) ADMIN_PASS_FILE="$2"; shift 2 ;;
        --bin) BIN="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$ADMIN_USER" ]; then
    echo "Usage: $0 --admin-user USER [--admin-pass-file FILE] [--listen 127.0.0.1:47732]" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
fi
if [ ! -f "$BIN" ]; then
    echo "Binary not found: $BIN. Build it first with ./scripts/build.sh" >&2
    exit 1
fi

PASS_TMP="$(mktemp /tmp/verstak-admin-pass.XXXXXX)"
trap 'rm -f "$PASS_TMP"' EXIT HUP INT TERM
if [ -n "$ADMIN_PASS_FILE" ]; then
    if [ ! -r "$ADMIN_PASS_FILE" ]; then
        echo "Admin password file is not readable" >&2
        exit 1
    fi
    cp "$ADMIN_PASS_FILE" "$PASS_TMP"
else
    printf 'Initial admin password: ' >&2
    stty -echo
    IFS= read -r ADMIN_PASS
    stty echo
    printf '\n' >&2
    printf '%s\n' "$ADMIN_PASS" > "$PASS_TMP"
    unset ADMIN_PASS
fi

INSTALL_DIR="/opt/verstak-sync-server"
DATA_DIR="/var/lib/verstak-sync-server"
ENV_DIR="/etc/verstak-server"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$BIN" "$INSTALL_DIR/verstak-sync-server"

if ! id -u "$USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi
install -d -o "$USER" -g "$USER" -m 0750 "$DATA_DIR"
chown "$USER:$USER" "$PASS_TMP"

# Initialize config as the service account. The process only receives the path
# to a 0600 temporary file, never password text in argv.
runuser -u "$USER" -- "$INSTALL_DIR/verstak-sync-server" \
    --data "$DATA_DIR" --listen "$LISTEN" --admin-user "$ADMIN_USER" \
    --admin-pass-file "$PASS_TMP" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

install -d -m 0750 "$ENV_DIR"
printf 'VERSTAK_LISTEN=%s\n' "$LISTEN" > "$ENV_DIR/env"
chmod 0640 "$ENV_DIR/env"
cp "$(dirname "$0")/../verstak-server.service" /etc/systemd/system/verstak-server.service
chmod 0644 /etc/systemd/system/verstak-server.service

systemctl daemon-reload
systemctl enable verstak-server
systemctl restart verstak-server

echo "Installed verstak-server listening on $LISTEN."
echo "Admin: http://$LISTEN/admin/login"
