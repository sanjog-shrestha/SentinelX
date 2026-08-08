package detect

import (
	"strings"
	"time"

	"sentinelx/internal/event"
)

func srcIP(ev *event.Event) string     { return ev.SrcIP }
func container(ev *event.Event) string { return ev.Container }

// DefaultRules ships eight detections, all triggerable in the lab.
func DefaultRules() []*Rule {
	return []*Rule{
		// 1. PORT SCAN — one source touching many DIFFERENT ports.
		// Distinct matters: 500 connections to port 80 is a busy client;
		// 20 connections to 20 ports is reconnaissance.
		{
			ID:          "port-scan",
			Title:       "Port scan detected",
			Severity:    "high",
			Description: "Single source contacted many distinct destination ports",
			Window:      60 * time.Second,
			Threshold:   15,
			Cooldown:    2 * time.Minute,
			Distinct:    true,
			MaxKeys:     5000,
			Match:       func(ev *event.Event) bool { return ev.DstPort > 0 },
			KeyBy:       srcIP,
			ValueOf:     func(ev *event.Event) string { return itoa(ev.DstPort) },
		},

		// 2. WEB ATTACK BURST — repeated IDS alerts from one source.
		{
			ID:          "web-attack-burst",
			Title:       "Repeated web attack signatures",
			Severity:    "high",
			Description: "Multiple web-application IDS alerts from one source",
			Window:      60 * time.Second,
			Threshold:   5,
			Cooldown:    2 * time.Minute,
			MaxKeys:     5000,
			Match: func(ev *event.Event) bool {
				return ev.Source == "suricata" && ev.Category == "web-application-attack"
			},
			KeyBy:   srcIP,
			ValueOf: func(ev *event.Event) string { return ev.Message },
		},

		// 3. BRUTE FORCE — the canonical threshold detection.
		{
			ID:          "auth-brute-force",
			Title:       "Authentication brute force",
			Severity:    "critical",
			Description: "Many failed authentication attempts from one source",
			Window:      60 * time.Second,
			Threshold:   20,
			Cooldown:    5 * time.Minute,
			MaxKeys:     5000,
			Match:       func(ev *event.Event) bool { return ev.Category == "authentication" },
			KeyBy:       srcIP,
			ValueOf:     func(ev *event.Event) string { return ev.Message },
		},

		// 4. HIGH SEVERITY BURST — signature-agnostic catch-all.
		{
			ID:          "high-severity-burst",
			Title:       "Burst of high severity events",
			Severity:    "medium",
			Description: "Many high/critical events from one source in a short time",
			Window:      120 * time.Second,
			Threshold:   10,
			Cooldown:    5 * time.Minute,
			MaxKeys:     5000,
			Match: func(ev *event.Event) bool {
				return ev.Severity == "high" || ev.Severity == "critical"
			},
			KeyBy:   srcIP,
			ValueOf: func(ev *event.Event) string { return ev.Message },
		},

		// 5. NEW HOST — threshold 1 means "alert on first occurrence".
		// The same struct that expresses "20 in 60 seconds" expresses
		// "any at all" — the payoff of making rules data.
		{
			ID:          "asset-new-host",
			Title:       "New host discovered on the network",
			Severity:    "high",
			Description: "A host not previously in the inventory was found",
			Window:      2 * time.Minute,
			Threshold:   1,
			Cooldown:    time.Hour,
			MaxKeys:     5000,
			Match: func(ev *event.Event) bool {
				return ev.Category == "asset" && ev.Severity == "high"
			},
			KeyBy:   srcIP,
			ValueOf: func(ev *event.Event) string { return ev.Message },
		},

		// 6. KNOWN-BAD SOURCE — any contact from a listed indicator.
		{
			ID:          "intel-known-bad",
			Title:       "Traffic from known-bad source",
			Severity:    "critical",
			Description: "Source IP matched a threat intelligence indicator",
			Window:      5 * time.Minute,
			Threshold:   1,
			Cooldown:    30 * time.Minute,
			MaxKeys:     5000,
			Match:       func(ev *event.Event) bool { return ev.IntelMatch },
			KeyBy:       srcIP,
			ValueOf: func(ev *event.Event) string {
				return ev.IntelSource + ":" + ev.IntelCategory
			},
		},

		// 7. SHELL IN CONTAINER — the highest-signal container detection
		// there is. Threshold 1: one is already too many.
		// NOTE the entity space widens here: KeyBy returns a CONTAINER NAME,
		// not an IP. LinkBy carries the container's IP so the correlator can
		// still tie this back to the attacker who caused it.
		{
			ID:          "runtime-shell",
			Title:       "Shell spawned inside a container",
			Severity:    "critical",
			Description: "Interactive shell or post-exploitation tooling executed in a container",
			Window:      5 * time.Minute,
			Threshold:   1,
			Cooldown:    10 * time.Minute,
			MaxKeys:     1000,
			Match: func(ev *event.Event) bool {
				return ev.Source == "falco" &&
					(strings.Contains(ev.Message, "Shell In Container") ||
						strings.Contains(ev.Message, "Network Tool In Container"))
			},
			KeyBy:   container,
			ValueOf: func(ev *event.Event) string { return ev.Process },
			LinkBy:  func(ev *event.Event) string { return ev.DstIP },
		},

		// 8. RUNTIME ACTIVITY BURST — several runtime alerts in one container.
		{
			ID:          "runtime-burst",
			Title:       "Multiple runtime security events in one container",
			Severity:    "high",
			Description: "A container produced several distinct runtime alerts in a short window",
			Window:      5 * time.Minute,
			Threshold:   3,
			Cooldown:    15 * time.Minute,
			MaxKeys:     1000,
			Match:       func(ev *event.Event) bool { return ev.Source == "falco" },
			KeyBy:       container,
			ValueOf:     func(ev *event.Event) string { return ev.Message },
			LinkBy:      func(ev *event.Event) string { return ev.DstIP },
		},
	}
}
