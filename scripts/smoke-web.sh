#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/verstak-sync-web.XXXXXX)"
PORT="47794"
DEBUG_PORT="9223"
cleanup() { kill "${BROWSER_PID:-}" 2>/dev/null || true; kill "${SERVER_PID:-}" 2>/dev/null || true; wait "${BROWSER_PID:-}" 2>/dev/null || true; wait "${SERVER_PID:-}" 2>/dev/null || true; if [[ "${KEEP_SMOKE_ARTIFACTS:-}" == "1" ]]; then printf 'web smoke artefacts retained at %s\n' "$TMP"; else rm -rf "$TMP"; fi; }
trap cleanup EXIT

printf '%s\n' 'browser-smoke-admin-password' > "$TMP/admin-pass"
chmod 600 "$TMP/admin-pass"
(cd "$ROOT" && go run ./cmd/server --data "$TMP/data" --listen "127.0.0.1:$PORT" --admin-user admin --admin-pass-file "$TMP/admin-pass") >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in {1..30}; do curl --noproxy '*' -fsS "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && break; sleep 1; done
curl --noproxy '*' -fsS "http://127.0.0.1:$PORT/" >/dev/null
chromium --headless --no-sandbox --disable-gpu --window-size=1440,900 --remote-debugging-port="$DEBUG_PORT" --user-data-dir="$TMP/chromium" about:blank >"$TMP/chromium.log" 2>&1 &
BROWSER_PID=$!
for _ in {1..30}; do curl --noproxy '*' -fsS "http://127.0.0.1:$DEBUG_PORT/json/list" >/dev/null 2>&1 && break; sleep 1; done
curl --noproxy '*' -fsS "http://127.0.0.1:$DEBUG_PORT/json/list" >/dev/null
CHROME_DEBUG_URL="http://127.0.0.1:$DEBUG_PORT" node "$ROOT/scripts/smoke-web-browser.mjs" "http://127.0.0.1:$PORT" "$TMP"
chromium --headless --no-sandbox --disable-gpu --screenshot="$TMP/public-mobile.png" --window-size=390,844 "http://127.0.0.1:$PORT/login" >/dev/null 2>&1
test -s "$TMP/public-en.png" && test -s "$TMP/public-mobile.png" && test -s "$TMP/admin-dashboard.png" && test -s "$TMP/admin-settings.png"
echo "interactive web browser smoke passed (set KEEP_SMOKE_ARTIFACTS=1 to retain temporary screenshots)"
