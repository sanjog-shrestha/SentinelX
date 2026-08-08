package detect

import (
	"time"

	"sentinelx/internal/event"
)

// Rule is a stateful threshold detector.
//
//	Match   — is this event relevant to me?
//	KeyBy   — which entity does it belong to?   (src_ip, or container name)
//	ValueOf — what am I counting?               (port, message, process)
//	LinkBy  — optional: an IP tying this alert to another entity's activity
//
// Set Distinct to count unique values rather than occurrences: that one flag
// is the difference between "20 requests" and "20 different ports".
type Rule struct {
	ID          string
	Title       string
	Severity    string
	Description string

	Window    time.Duration
	Threshold int
	Cooldown  time.Duration
	Distinct  bool
	MaxKeys   int // memory guard: max tracked entities

	Match   func(*event.Event) bool
	KeyBy   func(*event.Event) string
	ValueOf func(*event.Event) string
	LinkBy  func(*event.Event) string

	// state (guarded by Detector's mutex — never touched directly)
	windows   map[string]*window
	lastFired map[string]time.Time
}

func (r *Rule) eval(ev *event.Event, now time.Time) *Alert {
	if r.Match != nil && !r.Match(ev) {
		return nil
	}
	key := r.KeyBy(ev)
	if key == "" {
		return nil
	}

	w, ok := r.windows[key]
	if !ok {
		if r.MaxKeys > 0 && len(r.windows) >= r.MaxKeys {
			return nil // shed load rather than exhaust memory
		}
		w = newWindow(r.Window)
		r.windows[key] = w
	}

	w.add(ev.OccurredAt, r.ValueOf(ev))
	w.trim(now)

	n := w.count()
	if r.Distinct {
		n = w.distinct()
	}
	if n < r.Threshold {
		return nil
	}

	// Cooldown: suppress re-firing for the same entity.
	if last, fired := r.lastFired[key]; fired && now.Sub(last) < r.Cooldown {
		return nil
	}
	r.lastFired[key] = now

	// Capture the link from the event that TRIPPED the rule. It's the most
	// recent evidence, so it reflects the current state of the world.
	link := ""
	if r.LinkBy != nil {
		link = r.LinkBy(ev)
	}

	first, lastSeen := w.span()
	return &Alert{
		RuleID:    r.ID,
		Title:     r.Title,
		Severity:  r.Severity,
		Entity:    key,
		Count:     n,
		FirstSeen: first,
		LastSeen:  lastSeen,
		Evidence:  w.evidence(10),
		Link:      link,
	}
}

// sweep evicts entities with no recent activity, bounding memory.
func (r *Rule) sweep(now time.Time) int {
	removed := 0
	for key, w := range r.windows {
		w.trim(now)
		if w.count() == 0 {
			delete(r.windows, key)
			removed++
		}
	}
	for key, at := range r.lastFired {
		if now.Sub(at) > r.Cooldown*2 {
			delete(r.lastFired, key)
		}
	}
	return removed
}
