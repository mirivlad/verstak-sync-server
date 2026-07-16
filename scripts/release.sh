#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"

if [[ -z "$VERSION" || ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "usage: $0 <version>" >&2
  echo "example: $0 v0.1.0-alpha.1" >&2
  exit 2
fi
if [[ "$(go env GOOS)" != "linux" || "$(go env GOARCH)" != "amd64" ]]; then
  echo "sync-server release artifacts are currently built for linux/amd64" >&2
  exit 1
fi

echo "=== verstak sync server release $VERSION ==="
VERSION="$VERSION" "$ROOT/scripts/build.sh"

RELEASE_ROOT="${RELEASE_ROOT:-$ROOT/release}"
STAGING="$RELEASE_ROOT/verstak-sync-server-$VERSION-linux-amd64"
ARCHIVE="$RELEASE_ROOT/verstak-sync-server-linux-amd64-$VERSION.tar.gz"
rm -rf "$STAGING" "$ARCHIVE"
mkdir -p "$STAGING/scripts"

cp "$ROOT/build/bin/verstak-sync-server" "$STAGING/verstak-sync-server"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/verstak-server.service" "$STAGING/"
cp "$ROOT/scripts/install.sh" "$STAGING/scripts/install.sh"
tar -C "$RELEASE_ROOT" -czf "$ARCHIVE" "$(basename "$STAGING")"
(cd "$RELEASE_ROOT" && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS)

echo "release archive: $ARCHIVE"
echo "checksums:       $RELEASE_ROOT/SHA256SUMS"
