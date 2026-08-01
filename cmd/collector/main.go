package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/event"
	"sentinelx/internal/httpx"
)

type template struct{ source, category, severity, message string }

var templates = []template{
	{"auth", "authentication", "medium", "failed SSH login for user root"},
	{"auth", "authentication", "high", "failed SSH login for user admin"},
	{"firewall", "network", "low", "connection attempt on closed port 23"},
	{"firewall", "network", "medium", "outbound connection to unusual port 4444"},
	{"web", "http", "info", "GET /admin returned 404"},
	{"web", "http", "medium", "SQL keywords detected in query string"},
}

func randomEvent() event.Event {
	t := templates[rand.Intn(len(templates))]
	ip := "10.0.0." + strconv.Itoa(rand.Intn(254)+1)
	return event.Event{
		EventID:    event.NewID(),
		Source:     t.source,
		Category:   t.category,
		Severity:   t.severity,
		Message:    t.message + " (src " + ip + ")",
		OccurredAt: time.Now().UTC(),
	}
}

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

	js, err := bus.NewJetStream(ctx, nc)
	if err != nil {
		slog.Error("jetstream setup failed", "err", err)
		os.Exit(1)
	}

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ev := randomEvent()
				payload, _ := json.Marshal(ev)
				_, err := js.Publish(ctx, bus.SubjectEventsRaw, payload,
					jetstream.WithMsgID(ev.EventID))
				if err != nil {
					slog.Warn("publish failed", "err", err)
					continue
				}
				slog.Info("published", "event_id", ev.EventID, "severity", ev.Severity)
			}
		}
	}()

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
}
