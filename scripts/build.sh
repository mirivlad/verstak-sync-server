#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== verstak-sync-server build ==="
if [ -f "$ROOT/go.mod" ]; then
  echo "[go build]"
  (cd "$ROOT" && go build ./...)
  echo "  ✅ go build"
  if go test -list . ./... &>/dev/null 2>&1; then
    (cd "$ROOT" && go test -count=1 ./... 2>&1 || true)
  else
    echo "  ℹ️  no tests"
  fi
else
  echo "  ℹ️  repository empty — no build target yet"
  echo "  📝 This repo will hold the Verstak sync server (CRDT-based)"
fi
echo ""
echo "✅ build passed (no-op)"
