package detect

import (
	"sentinelx/internal/event"
	"time"
)

func srcIP(ev *event.Event) string { return ev.SrcIP }

func DefaultRules() []*Rule {
	return []*Rule{
		{
			ID:          "port-scan",
			Title:       "port scan detected",
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
		{
			ID:          "web-attack-burst",
			Title:       "Repeated web attack signatures",
			Severity:    "high",
			Description: "Multiple web-application IDS alerts from one source",
			Window:      60 * time.Second,
			Threshold:   5,
			Cooldown:    2 * time.Minute,
			MaxKeys:     5000,
			Match:       func(ev *event.Event) bool { return ev.Source == "suricata" && ev.Category == "web-application-attack" },
			KeyBy:       srcIP,
			ValueOf:     func(ev *event.Event) string { return ev.Message },
		},
		{
			ID:          "auth-brute-force",
			Title:       "Authentication brute-force",
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
		{
			ID:          "high-severity-brust",
			Title:       "Burst of high severity events",
			Severity:    "medium",
			Description: "Many high/critical events from one source in a short time",
			Window:      120 * time.Second,
			Threshold:   10,
			Cooldown:    5 * time.Minute,
			MaxKeys:     5000,
			Match:       func(ev *event.Event) bool { return ev.Severity == "high" || ev.Severity == "critical" },
			KeyBy:       srcIP,
			ValueOf:     func(ev *event.Event) string { return ev.Message },
		},
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
	}
}
