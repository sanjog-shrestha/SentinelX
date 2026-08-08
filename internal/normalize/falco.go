package normalize

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"sentinelx/internal/event"
)

type falcoAlert struct {
	Time         time.Time      `json:"time"`
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Output       string         `json:"output"`
	Tags         []string       `json:"tags"`
	OutputFields map[string]any `json:"output_fields"`
}

// Falco priorities are strings; map them onto our severity vocabulary.
func falcoSeverity(p string) string {
	switch strings.ToLower(p) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error", "warning":
		return "high"
	case "notice":
		return "medium"
	default:
		return "low"
	}
}

// containerIPs caches container-name -> IP resolutions.
//
// This is the bridge between two identity spaces: Falco speaks in container
// names, the rest of the platform speaks in IP addresses. Docker's embedded
// DNS resolves service names, so we strip compose's "<project>-<svc>-<n>"
// decoration back to the service name and look that up.
var (
	ipMu    sync.RWMutex
	ipCache = map[string]string{}
)

func resolveContainerIP(name string) string {
	if name == "" {
		return ""
	}
	ipMu.RLock()
	cached, ok := ipCache[name]
	ipMu.RUnlock()
	if ok {
		return cached
	}

	// "sentinelx-victim-1" -> "victim"
	service := name
	if parts := strings.Split(name, "-"); len(parts) >= 3 {
		service = strings.Join(parts[1:len(parts)-1], "-")
	}

	ip := ""
	if addrs, err := net.LookupHost(service); err == nil && len(addrs) > 0 {
		ip = addrs[0]
	}

	ipMu.Lock()
	ipCache[name] = ip // cache misses too — avoids hammering DNS on every event
	ipMu.Unlock()
	return ip
}

// Falco converts one events.json line into our envelope.
func Falco(line []byte) (*event.Event, error) {
	var a falcoAlert
	if err := json.Unmarshal(line, &a); err != nil {
		return nil, fmt.Errorf("falco unmarshal: %w", err)
	}
	if a.Rule == "" {
		return nil, nil // not an alert line
	}

	container := fieldStr(a.OutputFields, "container.name")
	proc := fieldStr(a.OutputFields, "proc.name")
	user := fieldStr(a.OutputFields, "user.name")

	occurred := a.Time
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}

	msg := a.Rule
	if a.Output != "" {
		msg = a.Rule + ": " + truncate(a.Output, 200)
	}

	return &event.Event{
		EventID:    event.DeterministicID(line),
		Source:     "falco",
		Category:   "runtime",
		Severity:   falcoSeverity(a.Priority),
		Message:    msg,
		OccurredAt: occurred.UTC(),
		Container:  container,
		Process:    proc,
		OSUser:     user,
		// DstIP is the container this happened INSIDE — the join key that
		// lets the correlator link this to a network attack on the same host.
		DstIP: resolveContainerIP(container),
	}, nil
}

func fieldStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
