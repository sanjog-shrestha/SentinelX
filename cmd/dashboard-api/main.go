package main

import (
	"context"
	"encoding/json"
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

// The dashboard-api aggregates data FROM the core api over plain HTTP,
// using Docker's DNS (http://api:8080). This is deliberate: you experience
// service-to-service REST calls, the pattern the real dashboard builds on.
func main() {
	cfg := config.Load("dashboard-api", ":8081")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nc, err := bus.Connect(cfg.NATSURL, cfg.ServiceName)
	if err != nil {
		slog.Error("nats connect failed", "err", err)
		os.Exit(1)
	}
	defer nc.Close()

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "api", Probe: func(ctx context.Context) error {
			_, err := fetchJSON(ctx, client, cfg.APIBaseURL+"/healthz")
			return err
		}},
	))

	mux.HandleFunc("GET /dashboard/v1/overview", func(w http.ResponseWriter, r *http.Request) {
		services, err1 := fetchJSON(r.Context(), client, cfg.APIBaseURL+"/api/v1/services")
		stats, err2 := fetchJSON(r.Context(), client, cfg.APIBaseURL+"/api/v1/events/stats")
		if err1 != nil || err2 != nil {
			httpx.WriteJSON(w, http.StatusBadGateway, map[string]string{"error": "api unreachable"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"generated_at": time.Now().UTC(),
			"services":     services["services"],
			"events":       stats,
		})
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("dashboard-api shut down cleanly")
}

func fetchJSON(ctx context.Context, client *http.Client, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, errors.New("upstream returned " + resp.Status)
	}
	var out map[string]any
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
