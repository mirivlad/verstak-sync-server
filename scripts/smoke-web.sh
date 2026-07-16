#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/verstak-sync-web.XXXXXX)"
PORT="47794"
cleanup() { kill "${SERVER_PID:-}" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

printf '%s\n' 'browser-smoke-admin-password' > "$TMP/admin-pass"
chmod 600 "$TMP/admin-pass"
(cd "$ROOT" && go run ./cmd/server --data "$TMP/data" --listen "127.0.0.1:$PORT" --admin-user admin --admin-pass-file "$TMP/admin-pass") >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in {1..30}; do curl --noproxy '*' -fsS "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 1; done
curl --noproxy '*' -fsS "http://127.0.0.1:$PORT/" >/dev/null
chromium --headless --no-sandbox --disable-gpu --screenshot="$TMP/public-en.png" --window-size=1440,900 "http://127.0.0.1:$PORT/" >/dev/null
chromium --headless --no-sandbox --disable-gpu --screenshot="$TMP/login-mobile.png" --window-size=390,844 "http://127.0.0.1:$PORT/login" >/dev/null
chromium --headless --no-sandbox --disable-gpu --screenshot="$TMP/admin-login.png" --window-size=1440,900 "http://127.0.0.1:$PORT/admin/login" >/dev/null
test -s "$TMP/public-en.png" && test -s "$TMP/login-mobile.png" && test -s "$TMP/admin-login.png"
echo "web browser smoke passed (screenshots were kept only for this run: $TMP)"
