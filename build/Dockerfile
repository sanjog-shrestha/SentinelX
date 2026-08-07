# ─────────────────────────────────────────────────────────────
# SentinelX — one image, eight binaries
#
# Stage 1 compiles every service in ./cmd/... in a single pass, so shared
# packages compile once instead of once per service. On a small host this is
# the difference between an OOM-killed parallel build and a working one.
#
# Stage 2 is a minimal Alpine runtime. Each container picks its binary via
# `command: ["<service>"]` in docker-compose.yml.
# ─────────────────────────────────────────────────────────────

# ── Stage 1: build ─────────────────────────────────────────────
FROM golang:1.24-alpine AS build
WORKDIR /src

COPY . .

# -o /out/ requires the directory to exist when building multiple packages.
# CGO_ENABLED=0 produces a static binary that runs on bare Alpine.
RUN mkdir -p /out && \
    go mod tidy && \
    CGO_ENABLED=0 go build -o /out/ ./cmd/...

# Fail the BUILD, loudly, if a service is missing. Without this, a package
# that isn't `package main` produces no binary and no error — the failure
# only surfaces later as "executable file not found in $PATH".
RUN for s in api collector detector dashboard-api correlator asset-manager ai-engine intel; do \
    test -x /out/$s || { echo "MISSING BINARY: $s"; exit 1; }; \
    done && \
    ls -la /out

# ── Stage 2: runtime ───────────────────────────────────────────
FROM alpine:3.20

# Only services that need extra tooling pass this in.
# asset-manager passes RUNTIME_PKGS=nmap; everything else builds a shared image.
ARG RUNTIME_PKGS=""
RUN if [ -n "$RUNTIME_PKGS" ]; then apk add --no-cache $RUNTIME_PKGS; fi

# Non-root by default. A security platform that runs everything as root is
# a contradiction — and it keeps nmap constrained to TCP connect scans,
# which is the trade we chose deliberately in Phase 5.
RUN adduser -D -u 10001 appuser

COPY --from=build /out/ /usr/local/bin/

USER appuser

# No ENTRYPOINT: docker-compose.yml supplies `command: ["<service>"]`.