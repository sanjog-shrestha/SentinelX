package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"sentinelx/internal/event"
)

// Alert is a pattern found across many events.
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

	// Link (Phase 9) ties this alert to a DIFFERENT entity's activity.
	// Runtime alerts are keyed by container name, but carry the container's
	// IP here so the correlator can attach them to the network incident of
	// whoever was attacking that host. Empty for purely network alerts.
	Link string `json:"link,omitempty"`
}

// Detector runs every rule over every event.
// The mutex exists because JetStream's Consume callback may run concurrently,
// and concurrent map writes crash Go outright.
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
			// Deterministic ID: (rule, entity, minute). A restart mid-burst
			// cannot insert the same alert twice.
			a.AlertID = NewAlertID(a.RuleID+"|"+a.Entity, now.Truncate(time.Minute))
			alerts = append(alerts, *a)
		}
	}
	return alerts
}

// NewAlertID builds a deterministic ID from a seed and a timestamp.
// Exported so the correlator can mint incident IDs the same way.
func NewAlertID(seed string, at time.Time) string {
	sum := sha256.Sum256([]byte(seed + "|" + at.Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:16])
}

// Sweep evicts idle entities to bound memory.
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

// Stats powers /detector/v1/state — being able to SEE engine state is what
// makes threshold tuning possible.
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
