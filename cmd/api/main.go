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
	"sentinelx/internal/event"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
)

func main() {
	cfg := config.Load("api", ":8080")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

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
		var e event.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if e.Source == "" || e.Message == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "source and message are required"})
			return
		}
		if e.EventID == "" {
			e.EventID = event.NewID()
		}
		if e.Category == "" {
			e.Category = "generic"
		}
		if e.Severity == "" {
			e.Severity = "info"
		}
		if e.OccurredAt.IsZero() {
			e.OccurredAt = time.Now().UTC()
		}
		if _, err := pg.InsertEvent(r.Context(), &e); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, e)
	})

	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		events, err := pg.ListEvents(r.Context(), parseLimit(r, 50))
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

	mux.HandleFunc("GET /api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		alerts, err := pg.ListAlerts(r.Context(), parseLimit(r, 50))
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(alerts), "alerts": alerts})
	})

	mux.HandleFunc("GET /api/v1/assets", func(w http.ResponseWriter, r *http.Request) {
		assets, err := pg.ListAssets(r.Context(), parseLimit(r, 200))
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(assets), "assets": assets})
	})

	mux.HandleFunc("GET /api/v1/assets/changes", func(w http.ResponseWriter, r *http.Request) {
		changes, err := pg.ListChanges(r.Context(), parseLimit(r, 50))
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(changes), "changes": changes})
	})

	mux.HandleFunc("GET /api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		incidents, err := pg.ListIncidents(r.Context(), parseLimit(r, 50))
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"count": len(incidents), "incidents": incidents})
	})

	mux.HandleFunc("GET /api/v1/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		inc, err := pg.GetIncident(r.Context(), r.PathValue("id"))
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if inc == nil {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, inc)
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("api shut down cleanly")
}

func parseLimit(r *http.Request, def int) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			return n
		}
	}
	return def
}
