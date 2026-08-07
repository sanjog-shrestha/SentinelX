package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/httpx"
	"sentinelx/internal/intel"
	"sentinelx/internal/store"
)

type service struct {
	cfg   config.Config
	pg    *store.Postgres
	rdb   *store.Redis
	feeds []intel.Feed
	http  *http.Client

	mu        sync.Mutex
	lastSync  time.Time
	lastCount int
	errs      map[string]string
}

func main() {
	cfg := config.Load("intel", ":8087")

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
	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

	s := &service{
		cfg:   cfg,
		pg:    pg,
		rdb:   rdb,
		feeds: intel.DefaultFeeds(cfg.IntelCustomPath),
		http:  &http.Client{Timeout: 60 * time.Second},
		errs:  map[string]string{},
	}
	go s.loop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "postgres", Probe: pg.Ping},
		httpx.Check{Name: "redis", Probe: rdb.Ping},
	))

	mux.HandleFunc("GET /intel/v1/status", func(w http.ResponseWriter, r *http.Request) {
		stats, _ := s.pg.IndicatorStats(r.Context())
		s.mu.Lock()
		defer s.mu.Unlock()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"last_sync":   s.lastSync,
			"last_count":  s.lastCount,
			"feed_errors": s.errs,
			"indicators":  stats,
		})
	})

	mux.HandleFunc("POST /intel/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		go s.syncOnce(context.Background())
		httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "sync started"})
	})

	mux.HandleFunc("POST /intel/v1/indicators", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Indicator  string `json:"indicator"`
			Category   string `json:"category"`
			Confidence int    `json:"confidence"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Indicator == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "indicator is required"})
			return
		}
		if body.Category == "" {
			body.Category = "manual"
		}
		if body.Confidence == 0 {
			body.Confidence = 90
		}
		if err := s.pg.AddCustomIndicator(r.Context(), body.Indicator, body.Category,
			body.Confidence, 30*24*time.Hour); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		go s.syncOnce(context.Background())
		httpx.WriteJSON(w, http.StatusCreated, map[string]string{"indicator": body.Indicator})
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func (s *service) loop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	s.syncOnce(ctx)

	t := time.NewTicker(s.cfg.IntelInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncOnce(ctx)
		}
	}
}

func (s *service) syncOnce(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()

	total := 0
	errs := map[string]string{}

	for _, f := range s.feeds {
		indicators, err := intel.Fetch(ctx, f, s.http)
		if err != nil {
			errs[f.Name] = err.Error()
			slog.Warn("feed fetch failed", "feed", f.Name, "err", err)
			continue
		}
		n, err := s.pg.UpsertIndicators(ctx, indicators)
		if err != nil {
			errs[f.Name] = err.Error()
			slog.Warn("feed store failed", "feed", f.Name, "err", err)
			continue
		}
		total += n
		slog.Info("feed ingested", "feed", f.Name, "indicators", n)
	}

	if _, err := s.pg.PurgeExpired(ctx); err != nil {
		slog.Warn("purge failed", "err", err)
	}

	active, err := s.pg.ActiveIndicators(ctx)
	if err != nil {
		slog.Error("load active indicators failed", "err", err)
		return
	}
	if err := intel.Publish(ctx, s.rdb.Client, active); err != nil {
		slog.Error("cache publish failed", "err", err)
		return
	}

	s.mu.Lock()
	s.lastSync = time.Now().UTC()
	s.lastCount = len(active)
	s.errs = errs
	s.mu.Unlock()

	slog.Info("intel sync complete", "ingested", total, "active_cached", len(active))
}
