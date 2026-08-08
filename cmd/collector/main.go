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
	"sentinelx/internal/normalize"
	"sentinelx/internal/tail"
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

	publish := func(ev *event.Event) {
		payload, _ := json.Marshal(ev)
		_, err := js.Publish(ctx, bus.SubjectEventsRaw, payload, jetstream.WithMsgID(ev.EventID))
		if err != nil {
			slog.Warn("publish failed", "err", err)
			return
		}
		slog.Info("published", "source", ev.Source, "severity", ev.Severity, "msg", ev.Message)
	}

	if cfg.SuricataEve != "" {
		lines := make(chan string, 256)
		go tail.Follow(ctx, cfg.SuricataEve, lines)
		go func() {
			for line := range lines {
				ev, err := normalize.Suricata([]byte(line))
				if err != nil {
					slog.Warn("suricata parse failed", "err", err)
					continue
				}
				if ev != nil {
					publish(ev)
				}
			}
		}()
	}

	if cfg.ZeekDir != "" {
		lines := make(chan string, 256)
		go tail.Follow(ctx, cfg.ZeekDir+"/conn.log", lines)
		go func() {
			for line := range lines {
				ev, err := normalize.ZeekConn([]byte(line))
				if err != nil {
					slog.Warn("zeek parse failed", "err", err)
					continue
				}
				if ev != nil {
					publish(ev)
				}
			}
		}()
	}

	// ── Source 4: Falco runtime alerts ──────────────────────────
	// Identical shape to the other two sources — that's the payoff of the
	// tail → normalize → publish pattern.
	if cfg.FalcoLog != "" {
		lines := make(chan string, 256)
		go tail.Follow(ctx, cfg.FalcoLog, lines)
		go func() {
			for line := range lines {
				ev, err := normalize.Falco([]byte(line))
				if err != nil {
					slog.Warn("falco parse failed", "err", err)
					continue
				}
				if ev != nil {
					publish(ev)
				}
			}
		}()
	}

	if cfg.Simulate {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ev := randomEvent()
					publish(&ev)
				}
			}
		}()
	}

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
