#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-verstak-sync-server:container-smoke}"
CONTAINER="verstak-sync-smoke-$$"
INIT_CONTAINER="verstak-sync-init-smoke-$$"
VOLUME="verstak-sync-smoke-$$"
RESTORE_VOLUME="verstak-sync-restore-smoke-$$"
COOKIE_JAR="$(mktemp)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$INIT_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  docker volume rm "$RESTORE_VOLUME" >/dev/null 2>&1 || true
  rm -f "$COOKIE_JAR"
}
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null
[[ "$(docker image inspect -f '{{.Config.User}}' "$IMAGE")" == "10001:10001" ]]
docker volume create "$VOLUME" >/dev/null
docker volume create "$RESTORE_VOLUME" >/dev/null

# The first-run password is delivered only through stdin, never via a stack
# environment variable or a process argument.
if docker run --rm --network none "$IMAGE" --help 2>&1 | grep -q -- '-init-admin'; then
  printf '%s\n' 'container-smoke-password' | docker run --rm -i --network none \
    --mount "type=volume,src=$VOLUME,dst=/data" "$IMAGE" \
    --data /data --init-admin --admin-user smoke --admin-pass-stdin
else
  # Older releases create the admin on normal startup rather than exiting.
  printf '%s\n' 'container-smoke-password' | docker run --rm -i --name "$INIT_CONTAINER" \
    --network none --mount "type=volume,src=$VOLUME,dst=/data" "$IMAGE" \
    --data /data --admin-user smoke --admin-pass-stdin >/dev/null 2>&1 &
  bootstrap_pid=$!
  for attempt in $(seq 1 30); do
    if docker run --rm --network none --mount "type=volume,src=$VOLUME,dst=/data,readonly" \
      --entrypoint test "$IMAGE" -s /data/config.yml; then
      break
    fi
    sleep 1
  done
  docker run --rm --network none --mount "type=volume,src=$VOLUME,dst=/data,readonly" \
    --entrypoint test "$IMAGE" -s /data/config.yml
  docker stop "$INIT_CONTAINER" >/dev/null
  wait "$bootstrap_pid" || true
fi

docker run -d --name "$CONTAINER" \
  --mount "type=volume,src=$VOLUME,dst=/data" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e VERSTAK_LISTEN=0.0.0.0:47732 -p 127.0.0.1::47732 "$IMAGE" >/dev/null

for attempt in $(seq 1 60); do
  if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]; then
    break
  fi
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]

address="$(docker port "$CONTAINER" 47732/tcp)"
curl --fail --silent --show-error "http://$address/readyz" | grep -q '"status":"ok"'
login_page="$(curl --fail --silent --show-error -c "$COOKIE_JAR" "http://$address/admin/login")"
csrf="$(printf '%s' "$login_page" | sed -n 's/.*name="locale_csrf" value="\([^"]*\)".*/\1/p' | head -n 1)"
[[ -n "$csrf" ]]
status="$(curl --silent --show-error -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  --data-urlencode "locale_csrf=$csrf" --data-urlencode 'username=smoke' \
  --data-urlencode 'password=container-smoke-password' \
  -o /dev/null -w '%{http_code}' "http://$address/admin/login")"
[[ "$status" == 303 ]]
grep -q 'admin_session' "$COOKIE_JAR"

docker stop "$CONTAINER" >/dev/null
docker run --rm --network none --mount "type=volume,src=$VOLUME,dst=/data,readonly" \
  --entrypoint /bin/sh "$IMAGE" -c \
  'test -s /data/config.yml && test -s /data/server.db && test -d /data/blobs'
docker start "$CONTAINER" >/dev/null
for attempt in $(seq 1 60); do
  if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]; then
    break
  fi
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]

docker stop "$CONTAINER" >/dev/null
docker run --rm --user 0 --network none \
  --mount "type=volume,src=$VOLUME,dst=/source,readonly" \
  --mount "type=volume,src=$RESTORE_VOLUME,dst=/data" \
  --entrypoint /bin/sh "$IMAGE" -c \
  'tar -C /source -cf /tmp/backup.tar . && tar -C /data -xf /tmp/backup.tar && chown -R 10001:10001 /data'
docker run --rm --network none --mount "type=volume,src=$RESTORE_VOLUME,dst=/data,readonly" \
  --entrypoint /bin/sh "$IMAGE" -c \
  'test -s /data/config.yml && test -s /data/server.db && test -d /data/blobs'
docker rm "$CONTAINER" >/dev/null
docker run -d --name "$CONTAINER" \
  --mount "type=volume,src=$RESTORE_VOLUME,dst=/data" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e VERSTAK_LISTEN=0.0.0.0:47732 -p 127.0.0.1::47732 "$IMAGE" >/dev/null
for attempt in $(seq 1 60); do
  if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]; then
    break
  fi
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")" == healthy ]]

echo "Container smoke passed: non-root image, admin login, readiness, web UI, restart, data restore"
