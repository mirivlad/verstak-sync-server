#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PUBLISHER="$ROOT/scripts/publish-github-release.sh"
VERSION="v0.0.0-test"
REPOSITORY="mirivlad/verstak-sync-server"
ASSET_NAME="verstak-sync-server-linux-amd64-${VERSION}.tar.gz"
STALE_ASSET="verstak-sync-server-linux-amd64-v0.0.0-stale.tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ ! -x "$PUBLISHER" ]]; then
  echo "publisher is missing or not executable: $PUBLISHER" >&2
  exit 1
fi

mkdir -p "$WORK/bin" "$WORK/release" "$WORK/release-notes" "$WORK/state"
LOG="$WORK/log"
export LOG
printf '## Highlights\n\nHuman-readable release notes.\n' > "$WORK/release-notes/$VERSION.md"

cat > "$WORK/release.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf 'release:%s\n' "$1" >> "$LOG"
printf 'archive\n' > "$VERSTAK_RELEASE_DIR/verstak-sync-server-linux-amd64-$1.tar.gz"
printf 'checksum\n' > "$VERSTAK_RELEASE_DIR/SHA256SUMS"
SCRIPT
chmod +x "$WORK/release.sh"

printf 'stale archive\n' > "$WORK/release/$STALE_ASSET"

cat > "$WORK/bin/git" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$PWD" != "${EXPECTED_ROOT:?}" ]]; then
  echo "publisher did not enter repository root: $PWD" >&2
  exit 1
fi
case "${1:-}" in
  status) exit 0 ;;
  branch) echo main ;;
  fetch) printf 'fetch\n' >> "$LOG" ;;
  rev-parse)
    if [[ "${2:-}" == "-q" ]]; then
      if [[ -f "$TEST_STATE/tag" ]]; then echo test-commit; exit 0; fi
      exit 1
    fi
    echo test-commit
    ;;
  describe) echo v0.0.0-previous ;;
  tag) touch "$TEST_STATE/tag"; printf 'tag:%s\n' "${3:-}" >> "$LOG" ;;
  push) printf 'push:%s:%s\n' "${2:-}" "${3:-}" >> "$LOG" ;;
  *) echo "unexpected git invocation: $*" >&2; exit 1 ;;
esac
SCRIPT
chmod +x "$WORK/bin/git"

cat > "$WORK/bin/gh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}:${2:-}" in
  auth:status) printf 'auth\n' >> "$LOG" ;;
  release:view)
    if [[ -f "$TEST_STATE/release" ]]; then echo https://github.example/release; else exit 1; fi
    ;;
  release:create) touch "$TEST_STATE/release"; printf 'create:%s\n' "$*" >> "$LOG" ;;
  release:upload) printf 'upload:%s\n' "$*" >> "$LOG" ;;
  *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
SCRIPT
chmod +x "$WORK/bin/gh"

run_publisher() {
  VERSTAK_RELEASE_SCRIPT="$WORK/release.sh" \
  VERSTAK_RELEASE_DIR="$WORK/release" \
  VERSTAK_RELEASE_NOTES_DIR="$WORK/release-notes" \
  GIT_BIN="$WORK/bin/git" \
  GH_BIN="$WORK/bin/gh" \
  EXPECTED_ROOT="$ROOT" \
  TEST_STATE="$WORK/state" \
  "$PUBLISHER" "$VERSION"
}

run_publisher
grep -Fqx "release:$VERSION" "$LOG"
grep -Fqx "tag:$VERSION" "$LOG"
grep -Fqx "push:origin:refs/tags/$VERSION" "$LOG"
grep -F "release create $VERSION" "$LOG" >/dev/null
grep -F "$ASSET_NAME" "$LOG" >/dev/null
grep -F "SHA256SUMS" "$LOG" >/dev/null
grep -F -- "--notes-file $WORK/release-notes/$VERSION.md" "$LOG" >/dev/null
grep -F -- "--generate-notes" "$LOG" >/dev/null
grep -F -- "--notes-start-tag v0.0.0-previous" "$LOG" >/dev/null
grep -F -- "--prerelease" "$LOG" >/dev/null
if grep -F -- "--latest" "$LOG" >/dev/null; then
  echo "alpha release was incorrectly marked latest" >&2
  exit 1
fi
if grep -F "$STALE_ASSET" "$LOG" >/dev/null; then
  echo "publisher uploaded an archive from a different release version" >&2
  exit 1
fi

run_publisher
grep -F "release upload $VERSION" "$LOG" >/dev/null

echo "GitHub release publisher test passed"
