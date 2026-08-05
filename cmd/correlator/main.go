package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/detect"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
)

const maxDeliver = 5

func main() {
	cfg := config.Load("correlator", ":8085")
	idle := cfg.IncidentIdleTimeout

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pg, err := store.NewPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		slog.Error("postgres init failed", "err", err)
		os.Exit(1)
	}
	defer pg.Pool.Close()

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

	stream, err := js.Stream(ctx, bus.StreamEvents)
	if err != nil {
		slog.Error("stream lookup failed", "err", err)
		os.Exit(1)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "correlator",
		FilterSubject: bus.SubjectAlerts,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    maxDeliver,
	})
	if err != nil {
		slog.Error("consumer setup failed", "err", err)
		os.Exit(1)
	}

	handle := func(msg jetstream.Msg) {
		hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := process(hctx, pg, js, idle, msg.Data()); err != nil {
			slog.Warn("correlation failed", "err", err)
			meta, _ := msg.Metadata()
			if meta != nil && meta.NumDelivered >= maxDeliver {
				slog.Error("giving up on alert", "deliveries", meta.NumDelivered)
				_ = msg.Ack()
				return
			}
			_ = msg.NakWithDelay(2 * time.Second)
			return
		}
		_ = msg.Ack()
	}

	cc, err := cons.Consume(handle)
	if err != nil {
		slog.Error("consume failed", "err", err)
		os.Exit(1)
	}
	defer cc.Stop()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				closed, err := pg.CloseIdle(rctx, idle)
				cancel()
				if err != nil {
					slog.Warn("close idle failed", "err", err)
					continue
				}
				for _, inc := range closed {
					slog.Info("INCIDENT CLOSED",
						"incident", inc.IncidentID, "entity", inc.Entity,
						"severity", inc.Severity, "score", inc.Score, "alerts", inc.AlertCount)
				}
			}
		}
	}()

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)
	slog.Info("correlator running", "idle_timeout", idle.String())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "postgres", Probe: pg.Ping},
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

func process(ctx context.Context, pg *store.Postgres, js jetstream.JetStream,
	idle time.Duration, data []byte) error {

	var a detect.Alert
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("unmarshal alert: %w", err)
	}
	if a.AlertID == "" || a.Entity == "" {
		return errors.New("alert missing alert_id or entity")
	}

	inc, isNew, dup, err := pg.AttachAlert(ctx, a, idle)
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	if dup {
		return nil
	}

	verb := "INCIDENT UPDATED"
	if isNew {
		verb = "INCIDENT OPENED"
	}
	slog.Warn(verb,
		"incident", inc.IncidentID, "entity", inc.Entity,
		"severity", inc.Severity, "score", inc.Score,
		"stages", inc.Stages, "alerts", inc.AlertCount)

	payload, _ := json.Marshal(inc)
	if _, err := js.Publish(ctx, bus.SubjectIncidents, payload); err != nil {
		slog.Warn("incident publish failed", "err", err)
	}
	return nil
}
