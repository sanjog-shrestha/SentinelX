# ── Stage 1: build ─────────────────────────────────────────────
FROM golang:1.24-alpine AS build
ARG SERVICE
WORKDIR /src 

COPY go.mod ./
COPY . .

RUN go mod tidy && CGO_ENABLED=0 go build -o /out/app ./cmd/${SERVICE}

# ── Stage 2: runtime ───────────────────────────────────────────
FROM alpine:3.20
ARG RUNTIME_PKGS=""
RUN if [ -n "$RUNTIME_PKGS" ]; then apk add --no-cache $RUNTIME_PKGS; fi
RUN adduser -D -u 10001 appuser
COPY --from=build /out/app /usr/local/bin/app
USER appuser
ENTRYPOINT ["/usr/local/bin/app"]