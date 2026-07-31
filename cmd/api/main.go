package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
)

func main() {
	cfg := config.Load("api", ":8080")

	// ctx is cancelled when Docker sends SIGTERM — everything downstream
	// (heartbeats, HTTP server) watches this one context to know when to stop.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── Dependencies ────────────────────────────────────────────
	pg, err := store.NewPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		slog.Error("postgres init failed", "err", err)
		os.Exit(1)
	}
	defer pg.Pool.Close()

	rdb := store.NewRedis(cfg.RedisAddr)
	defer rdb.Client.Close()

	nc, err := bus.Connect(cfg.NATSURL, cfg.ServiceName)
	if err != nil {
		slog.Error("nats connect failed", "err", err)
		os.Exit(1)
	}
	defer nc.Close()

	// ── Subscribe: every heartbeat on the bus is recorded in Redis ──
	sub, err := nc.Subscribe(bus.HeartbeatSubject, func(msg *nats.Msg) {
		var hb bus.Heartbeat
		if err := json.Unmarshal(msg.Data, &hb); err != nil {
			slog.Warn("bad heartbeat payload", "err", err)
			return
		}
		hctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rdb.RecordHeartbeat(hctx, hb.Service, hb.SentAt); err != nil {
			slog.Warn("record heartbeat failed", "err", err)
		}
	})
	if err != nil {
		slog.Error("subscribe failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// The api announces itself too.
	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

	// ── Routes ──────────────────────────────────────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "postgres", Probe: pg.Ping},
		httpx.Check{Name: "redis", Probe: rdb.Ping},
		httpx.Check{Name: "nats", Probe: func(context.Context) error {
			if !nc.IsConnected() {
				return errors.New("not connected")
			}
			return nil
		}},
	))

	mux.HandleFunc("GET /api/v1/services", func(w http.ResponseWriter, r *http.Request) {
		statuses, err := rdb.ServiceStatuses(r.Context(), 30*time.Second)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"services": statuses})
	})

	mux.HandleFunc("POST /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		var e store.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if e.Source == "" || e.Message == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "source and message are required"})
			return
		}
		if e.Category == "" {
			e.Category = "generic"
		}
		if e.Severity == "" {
			e.Severity = "info"
		}
		if err := pg.InsertEvent(r.Context(), &e); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, e)
	})

	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		events, err := pg.ListEvents(r.Context(), limit)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(events), "events": events})
	})

	mux.HandleFunc("GET /api/v1/events/stats", func(w http.ResponseWriter, r *http.Request) {
		n, err := pg.CountEvents(r.Context())
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"total_events": n})
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("api shut down cleanly")
}
