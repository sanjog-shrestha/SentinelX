package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/httpx"
)

// Phase 1: the collector only proves it exists — it connects to NATS,
// heartbeats, and serves health endpoints. In Phase 2 it starts publishing
// real events; in Phase 3 it reads Suricata's eve.json and Zeek logs.
func main() {
	cfg := config.Load("collector", ":8082")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nc, err := bus.Connect(cfg.NATSURL, cfg.ServiceName)
	if err != nil {
		slog.Error("nats connect failed", "err", err)
		os.Exit(1)
	}
	defer nc.Close()

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)
	slog.Info("collector running — event collection arrives in Phase 2")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "nats", Probe: func(context.Context) error {
			if !nc.IsConnected() {
				return errors.New("not connected")
			}
			return nil
		}},
	))

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("collector shut down cleanly")
}
