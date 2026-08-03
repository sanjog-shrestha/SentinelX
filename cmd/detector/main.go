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

	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/detect"
	"sentinelx/internal/event"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const maxDeliver = 5

func main() {
	cfg := config.Load("detector", ":8083")

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

	engine := detect.New(detect.DefaultRules())

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				engine.Sweep(time.Now().UTC())
			}
		}
	}()

	stream, err := js.Stream(ctx, bus.StreamEvents)
	if err != nil {
		slog.Error("stream lookup failed", "err", err)
		os.Exit(1)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "detector",
		FilterSubject: bus.SubjectEventsRaw,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    maxDeliver,
	})
	if err != nil {
		slog.Error("consumer setup failed", "err", err)
		os.Exit(1)
	}

	handle := func(msg jetstream.Msg) {
		hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := process(hctx, pg, js, engine, msg.Data())
		if err == nil {
			_ = msg.Ack()
			return
		}

		slog.Warn("processing failed", "err", err)
		meta, _ := msg.Metadata()
		if meta != nil && meta.NumDelivered >= maxDeliver {
			if _, dlqErr := js.Publish(hctx, bus.SubjectEventsDLQ, msg.Data()); dlqErr != nil {
				slog.Error("dlq publish failed", "err", dlqErr)
				_ = msg.NakWithDelay(5 * time.Second)
				return
			}
			slog.Error("message moved to DLQ", "deliveries", meta.NumDelivered)
			_ = msg.Ack()
			return
		}
		_ = msg.NakWithDelay(2 * time.Second)
	}

	cc, err := cons.Consume(handle)
	if err != nil {
		slog.Error("consume failed", "err", err)
		os.Exit(1)
	}
	defer cc.Stop()

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)
	slog.Info("detector consuming", "subject", bus.SubjectEventsRaw, "rules", len(detect.DefaultRules()))

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

	mux.HandleFunc("GET /detector/v1/state", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, engine.Stats())
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("detector shut down cleanly")
}

func process(ctx context.Context, pg *store.Postgres, js jetstream.JetStream,
	engine *detect.Detector, data []byte) error {

	var ev event.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if ev.EventID == "" {
		return errors.New("event missing event_id")
	}

	inserted, err := pg.InsertEvent(ctx, &ev)
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	if !inserted {
		slog.Info("duplicate delivery ignored", "event_id", ev.EventID)
		return nil
	}

	for _, alert := range engine.Eval(&ev, time.Now().UTC()) {
		stored, err := pg.InsertAlert(ctx, &alert)
		if err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
		if !stored {
			continue
		}

		slog.Warn("ALERT",
			"rule", alert.RuleID,
			"entity", alert.Entity,
			"count", alert.Count,
			"severity", alert.Severity)

		payload, marshalErr := json.Marshal(alert)
		if marshalErr != nil {
			slog.Warn("alert marshal failed", "err", marshalErr)
			continue
		}
		if _, err := js.Publish(ctx, bus.SubjectAlerts, payload,
			jetstream.WithMsgID(alert.AlertID)); err != nil {
			slog.Warn("alert publish failed", "err", err)
		}
	}
	return nil
}
