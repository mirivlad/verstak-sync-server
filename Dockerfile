FROM golang:1.25.12-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG BUILD_COMMIT=unknown
RUN CGO_ENABLED=1 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X github.com/verstak/verstak-sync-server/internal/server.Version=${VERSION} -X github.com/verstak/verstak-sync-server/internal/server.BuildCommit=${BUILD_COMMIT}" \
    -o /out/verstak-sync-server ./cmd/server

FROM debian:bookworm-slim
ARG BUILD_COMMIT=unknown
LABEL org.opencontainers.image.source="https://github.com/mirivlad/verstak-sync-server" \
      org.opencontainers.image.revision="${BUILD_COMMIT}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 verstak && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin verstak && \
    mkdir /data && chown verstak:verstak /data
COPY --from=build /out/verstak-sync-server /usr/local/bin/verstak-sync-server

USER 10001:10001
EXPOSE 47732
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent --output /dev/null http://127.0.0.1:47732/readyz || exit 1
ENTRYPOINT ["/usr/local/bin/verstak-sync-server"]
CMD ["--data", "/data"]
