#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"
REPOSITORY="mirivlad/verstak-sync-server"
RELEASE_SCRIPT="${VERSTAK_RELEASE_SCRIPT:-$ROOT/scripts/release.sh}"
RELEASE_DIR="${VERSTAK_RELEASE_DIR:-$ROOT/release}"
GIT_BIN="${GIT_BIN:-git}"
GH_BIN="${GH_BIN:-gh}"

cd "$ROOT"

if [[ -z "$VERSION" || ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "usage: $0 <version>" >&2
  echo "example: $0 v0.1.0-alpha.1" >&2
  exit 2
fi
if ! command -v "$GH_BIN" >/dev/null; then
  echo "gh CLI is required to publish a GitHub Release" >&2
  exit 1
fi
if [[ "$("$GIT_BIN" branch --show-current)" != "main" ]]; then
  echo "GitHub releases must be published from main" >&2
  exit 1
fi
if [[ -n "$("$GIT_BIN" status --porcelain)" ]]; then
  echo "working tree must be clean before publishing a release" >&2
  exit 1
fi

"$GH_BIN" auth status
"$GIT_BIN" fetch origin main --tags
HEAD="$("$GIT_BIN" rev-parse HEAD)"
if [[ "$HEAD" != "$("$GIT_BIN" rev-parse origin/main)" ]]; then
  echo "local main must match origin/main before publishing a release" >&2
  exit 1
fi

"$RELEASE_SCRIPT" "$VERSION"

ARCHIVE="$RELEASE_DIR/verstak-sync-server-linux-amd64-$VERSION.tar.gz"
if [[ ! -f "$ARCHIVE" ]]; then
  echo "release archive not found: $ARCHIVE" >&2
  exit 1
fi
ASSETS=("$ARCHIVE")
if [[ -f "$RELEASE_DIR/SHA256SUMS" ]]; then
  ASSETS+=("$RELEASE_DIR/SHA256SUMS")
fi

if "$GIT_BIN" rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  if [[ "$("$GIT_BIN" rev-parse "${VERSION}^{commit}")" != "$HEAD" ]]; then
    echo "existing tag $VERSION does not point at HEAD" >&2
    exit 1
  fi
else
  "$GIT_BIN" tag -a "$VERSION" -m "Release $VERSION"
  "$GIT_BIN" push origin "refs/tags/$VERSION"
fi

if "$GH_BIN" release view "$VERSION" --repo "$REPOSITORY" >/dev/null 2>&1; then
  "$GH_BIN" release upload "$VERSION" "${ASSETS[@]}" --repo "$REPOSITORY" --clobber
else
  "$GH_BIN" release create "$VERSION" "${ASSETS[@]}" \
    --repo "$REPOSITORY" \
    --title "Verstak Sync Server $VERSION" \
    --generate-notes \
    --latest \
    --verify-tag
fi

echo "GitHub release:"
"$GH_BIN" release view "$VERSION" --repo "$REPOSITORY" --json url --jq .url
