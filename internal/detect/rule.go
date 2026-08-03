package detect

import (
	"sentinelx/internal/event"
	"time"
)

type Rule struct {
	ID          string
	Title       string
	Severity    string
	Description string

	Window    time.Duration
	Threshold int
	Cooldown  time.Duration
	Distinct  bool
	MaxKeys   int

	Match   func(*event.Event) bool
	KeyBy   func(*event.Event) string
	ValueOf func(*event.Event) string

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
			return nil
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

	if last, fired := r.lastFired[key]; fired && now.Sub(last) < r.Cooldown {
		return nil
	}
	r.lastFired[key] = now

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
	}
}

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
