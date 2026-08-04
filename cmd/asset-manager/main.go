package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"sentinelx/internal/asset"
	"sentinelx/internal/bus"
	"sentinelx/internal/config"
	"sentinelx/internal/event"
	"sentinelx/internal/httpx"
	"sentinelx/internal/store"
)

type scanner struct {
	cfg config.Config
	pg  *store.Postgres
	js  jetstream.JetStream

	mu        sync.Mutex // guards the fields below AND prevents overlapping scans
	running   bool
	lastRun   time.Time
	lastErr   string
	lastFound int
}

func main() {
	cfg := config.Load("asset-manager", ":8084")

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

	bus.StartHeartbeat(ctx, nc, cfg.ServiceName, 10*time.Second)

	s := &scanner{cfg: cfg, pg: pg, js: js}
	go s.loop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", httpx.HealthzHandler(cfg.ServiceName))
	mux.HandleFunc("GET /readyz", httpx.ReadyzHandler(
		httpx.Check{Name: "postgres", Probe: pg.Ping},
	))

	mux.HandleFunc("GET /assets/v1/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"targets":    cfg.ScanTargets,
			"interval":   cfg.ScanInterval.String(),
			"running":    s.running,
			"last_run":   s.lastRun,
			"last_error": s.lastErr,
			"last_found": s.lastFound,
		})
	})

	mux.HandleFunc("POST /assets/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		go s.runOnce(context.Background())
		httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "scan started"})
	})

	if err := httpx.Run(ctx, cfg.HTTPAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	slog.Info("asset-manager shut down cleanly")
}

func (s *scanner) loop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	s.runOnce(ctx)

	ticker := time.NewTicker(s.cfg.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			jitter := time.Duration(rand.Int63n(int64(10 * time.Second)))
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter):
			}
			s.runOnce(ctx)
		}
	}
}

func (s *scanner) runOnce(parent context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		slog.Warn("scan skipped — previous scan still running")
		return
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.lastRun = time.Now().UTC()
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(parent, s.cfg.ScanTimeout)
	defer cancel()

	started := time.Now().UTC()
	slog.Info("scan starting", "targets", s.cfg.ScanTargets)

	found, err := asset.Scan(ctx, s.cfg.ScanTargets)
	if err != nil {
		s.setErr(err.Error())
		slog.Error("scan failed", "err", err)
		return
	}

	previous, err := s.pg.OpenAssets(ctx)
	if err != nil {
		s.setErr(err.Error())
		slog.Error("load previous inventory failed", "err", err)
		return
	}

	changes := asset.Diff(previous, found, started)

	if err := s.pg.ApplyScan(ctx, found, started); err != nil {
		s.setErr(err.Error())
		slog.Error("apply scan failed", "err", err)
		return
	}

	s.setOK(len(found))
	slog.Info("scan complete",
		"open_ports", len(found),
		"changes", len(changes),
		"took", time.Since(started).String())

	for _, c := range changes {
		s.publishChange(ctx, c)
	}
}
func (s *scanner) publishChange(ctx context.Context, c asset.Change) {
	seed := c.Kind + "|" + c.Host + "|" + c.Proto + "|" + itoa(c.Port) + "|" +
		c.DetectedAt.Truncate(time.Minute).String()
	sum := sha256.Sum256([]byte(seed))
	id := hex.EncodeToString(sum[:16])

	stored, err := s.pg.InsertChange(ctx, id, c)
	if err != nil {
		slog.Warn("store change failed", "err", err)
		return
	}
	if !stored {
		return
	}

	severity := "medium"
	if c.Kind == asset.KindNewHost {
		severity = "high"
	}
	if c.Kind == asset.KindPortClosed {
		severity = "info"
	}

	ev := event.Event{
		EventID:    id,
		Source:     "asset-manager",
		Category:   "asset",
		Severity:   severity,
		Message:    c.Detail,
		OccurredAt: c.DetectedAt,
		SrcIP:      c.Host, // lets Phase 4 rules key on the host
		DstPort:    c.Port,
		Proto:      c.Proto,
	}

	payload, _ := json.Marshal(ev)
	if _, err := s.js.Publish(ctx, bus.SubjectEventsRaw, payload,
		jetstream.WithMsgID(ev.EventID)); err != nil {
		slog.Warn("publish change failed", "err", err)
		return
	}
	slog.Warn("ASSET CHANGE", "kind", c.Kind, "detail", c.Detail)
}

func (s *scanner) setErr(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = msg
}

func (s *scanner) setOK(found int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = ""
	s.lastFound = found
}

func itoa(i int) string {
	return event.Itoa(i)
}
