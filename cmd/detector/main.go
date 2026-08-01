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

		err := process(hctx, pg, msg.Data())
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
	slog.Info("detector consuming", "subject", bus.SubjectEventsRaw)

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

func process(ctx context.Context, pg *store.Postgres, data []byte) error {
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
	slog.Info("event stored", "event_id", ev.EventID, "severity", ev.Severity)
	return nil
}
