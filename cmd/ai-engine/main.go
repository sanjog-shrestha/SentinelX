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
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"sentinelx/internal/ai"
	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/correlate"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
)

type engine struct {
	cfg    config.Config
	pg     *store.Postgres
	client *ai.Client

	mu       sync.Mutex
	lastRun  map[string]time.Time
	analyzed int
	failed   int
	lastErr  string
}

func main() {
	cfg := config.Load("ai-engine", ":8086")

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

	e := &engine{
		cfg:     cfg,
		pg:      pg,
		client:  ai.New(cfg.OllamaURL, cfg.OllamaModel, cfg.AITimeout),
		lastRun: map[string]time.Time{},
	}

	if cfg.AIEnabled {
		go func() {
			if err := e.client.EnsureModel(context.Background()); err != nil {
				slog.Error("model pull failed — AI reports will fail until resolved", "err", err)
			}
		}()
	} else {
		slog.Warn("AI_ENABLED=false — running as a no-op consumer")
	}

	stream, err := js.Stream(ctx, bus.StreamEvents)
	if err != nil {
		slog.Error("stream lookup failed", "err", err)
		os.Exit(1)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "ai-engine",
		FilterSubject: bus.SubjectIncidents,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       5 * time.Minute,
		MaxDeliver:    2,
	})
	if err != nil {
		slog.Error("consumer setup failed", "err", err)
		os.Exit(1)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		defer func() { _ = msg.Ack() }()

		if !e.cfg.AIEnabled {
			return
		}
		hctx, cancel := context.WithTimeout(context.Background(), e.cfg.AITimeout+30*time.Second)
		defer cancel()

		if err := e.handle(hctx, msg.Data()); err != nil {
			e.recordFailure(err)
			slog.Warn("analysis failed", "err", err)
		}
	})
	if err != nil {
		slog.Error("consume failed", "err", err)
		os.Exit(1)
	}
	defer cc.Stop()

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)
	slog.Info("ai-engine running", "model", cfg.OllamaModel, "enabled", cfg.AIEnabled)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "postgres", Probe: pg.Ping},
		httpx.Check{Name: "ollama", Probe: func(c context.Context) error {
			if !cfg.AIEnabled {
				return nil
			}
			return e.client.Ping(c)
		}},
	))
	mux.HandleFunc("GET /ai/v1/status", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"enabled":    cfg.AIEnabled,
			"model":      cfg.OllamaModel,
			"min_score":  cfg.AIMinScore,
			"cooldown":   cfg.AICooldown.String(),
			"analyzed":   e.analyzed,
			"failed":     e.failed,
			"last_error": e.lastErr,
		})
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func (e *engine) handle(ctx context.Context, data []byte) error {
	var inc correlate.Incident
	if err := json.Unmarshal(data, &inc); err != nil {
		return fmt.Errorf("unmarshal incident: %w", err)
	}

	if inc.Score < e.cfg.AIMinScore {
		return nil
	}

	e.mu.Lock()
	last, seen := e.lastRun[inc.IncidentID]
	if seen && time.Since(last) < e.cfg.AICooldown {
		e.mu.Unlock()
		return nil
	}
	e.lastRun[inc.IncidentID] = time.Now()
	e.mu.Unlock()

	full, err := e.pg.GetIncident(ctx, inc.IncidentID)
	if err != nil {
		return fmt.Errorf("load incident: %w", err)
	}
	if full == nil {
		return nil
	}

	events, err := e.pg.EventsForEntity(ctx, full.Entity, full.FirstSeen.Add(-2*time.Minute), 60)
	if err != nil {
		return fmt.Errorf("load evidence: %w", err)
	}

	prompt := ai.Build(*full, events)
	started := time.Now()

	raw, err := e.client.GenerateJSON(ctx, ai.SystemPrompt, prompt)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	report, err := ai.Parse(raw)
	if err != nil {
		raw, err2 := e.client.GenerateJSON(ctx, ai.SystemPrompt,
			prompt+"\n\nIMPORTANT: return ONLY the JSON object. No prose, no markdown fences.")
		if err2 != nil {
			return fmt.Errorf("retry generate: %w", err2)
		}
		report, err = ai.Parse(raw)
		if err != nil {
			return fmt.Errorf("unusable model output: %w", err)
		}
	}

	if !ai.Grounded(report, full.Entity) {
		slog.Warn("report may be ungrounded — entity not mentioned",
			"incident", full.IncidentID, "entity", full.Entity)
	}

	if err := e.pg.UpsertReport(ctx, full.IncidentID, e.cfg.OllamaModel, report, full.Score); err != nil {
		return fmt.Errorf("store report: %w", err)
	}

	e.mu.Lock()
	e.analyzed++
	e.lastErr = ""
	e.mu.Unlock()

	slog.Info("AI REPORT",
		"incident", full.IncidentID,
		"entity", full.Entity,
		"confidence", report.Confidence,
		"took", time.Since(started).Round(time.Millisecond).String(),
		"summary", report.Summary)
	return nil
}

func (e *engine) recordFailure(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed++
	e.lastErr = err.Error()
}
