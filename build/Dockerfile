# ── Stage 1: build every service in one pass ───────────────────
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /out/ ./cmd/...

# ── Stage 2: runtime ───────────────────────────────────────────
FROM alpine:3.20
ARG RUNTIME_PKGS=""
RUN if [ -n "$RUNTIME_PKGS" ]; then apk add --no-cache $RUNTIME_PKGS; fi
RUN adduser -D -u 10001 appuser
COPY --from=build /out/ /usr/local/bin/
USER appuser
