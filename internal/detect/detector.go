package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sentinelx/internal/event"
	"strconv"
	"sync"
	"time"
)

type Alert struct {
	AlertID   string    `json:"alert_id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Entity    string    `json:"entity"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Evidence  []string  `json:"evidence"`
	CreatedAt time.Time `json:"created_at"`
}

type Detector struct {
	mu    sync.Mutex
	rules []*Rule
}

func New(rules []*Rule) *Detector {
	for _, r := range rules {
		r.windows = map[string]*window{}
		r.lastFired = map[string]time.Time{}
	}
	return &Detector{rules: rules}
}

func (d *Detector) Eval(ev *event.Event, now time.Time) []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []Alert
	for _, r := range d.rules {
		if a := r.eval(ev, now); a != nil {
			a.CreatedAt = now
			seed := a.RuleID + "|" + a.Entity + "|" + now.Truncate(time.Minute).String()
			sum := sha256.Sum256([]byte(seed))
			a.AlertID = hex.EncodeToString(sum[:16])
			alerts = append(alerts, *a)
		}
	}
	return alerts
}

func (d *Detector) Sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	total := 0
	for _, r := range d.rules {
		total += r.sweep(now)
	}
	if total > 0 {
		slog.Info("detector swept idle entities", "removed", total)
	}
}

func (d *Detector) Stats() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := map[string]any{}
	for _, r := range d.rules {
		tracked := map[string]int{}
		for key, w := range r.windows {
			n := w.count()
			if r.Distinct {
				n = w.distinct()
			}
			tracked[key] = n
		}
		out[r.ID] = map[string]any{
			"title":     r.Title,
			"window":    r.Window.String(),
			"threshold": r.Threshold,
			"distinct":  r.Distinct,
			"entities":  len(r.windows),
			"tracked":   tracked,
		}
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
