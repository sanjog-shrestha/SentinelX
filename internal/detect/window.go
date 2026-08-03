package detect

import (
	"time"
)

type observation struct {
	at    time.Time
	value string
}

type window struct {
	size  time.Duration
	items []observation
}

func newWindow(size time.Duration) *window {
	return &window{size: size}
}

func (w *window) add(at time.Time, value string) {
	w.items = append(w.items, observation{at: at, value: value})
}

func (w *window) trim(now time.Time) {
	cutoff := now.Add(-w.size)
	i := 0
	for i < len(w.items) && w.items[i].at.Before(cutoff) {
		i++
	}
	if i == 0 {
		return
	}
	remaining := make([]observation, len(w.items)-i)
	copy(remaining, w.items[i:])
	w.items = remaining
}

func (w *window) count() int { return len(w.items) }

func (w *window) distinct() int {
	seen := make(map[string]struct{}, len(w.items))
	for _, it := range w.items {
		seen[it.value] = struct{}{}
	}
	return len(seen)
}

func (w *window) evidence(n int) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for i := len(w.items) - 1; i >= 0 && len(out) < n; i-- {
		v := w.items[i].value
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func (w *window) span() (time.Time, time.Time) {
	if len(w.items) == 0 {
		return time.Time{}, time.Time{}
	}
	return w.items[0].at, w.items[len(w.items)-1].at
}
