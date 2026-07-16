#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/build/bin"
BINARY="$OUTPUT_DIR/verstak-sync-server"

echo "=== Verstak Sync Server Build ==="

# Check dependencies
if ! command -v go &>/dev/null; then
  echo "❌ go not found"
  exit 1
fi
echo "✅ go $(go version | awk '{print $3}')"

# Clean
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Build
echo "→ Building server binary..."
cd "$REPO_ROOT"
VERSION="${VERSION:-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
go build -ldflags "-X github.com/verstak/verstak-sync-server/internal/server.Version=$VERSION -X github.com/verstak/verstak-sync-server/internal/server.BuildCommit=$COMMIT" -o "$BINARY" ./cmd/server
echo "✅ Binary built: $BINARY"
ls -lh "$BINARY"

# Tests
echo "→ Running tests..."
go test ./...
echo "✅ Tests passed"

echo ""
echo "=== Build Complete ==="
echo "Binary: $BINARY"
echo "Run: $BINARY --help"
