package correlate

import "time"

type Incident struct {
	IncidentID string          `json:"incident_id"`
	Entity     string          `json:"entity"`
	Title      string          `json:"title"`
	Status     string          `json:"status"`
	Severity   string          `json:"severity"`
	Score      int             `json:"score"`
	Stages     []string        `json:"stages"`
	AlertCount int             `json:"alert_count"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	ClosedAt   *time.Time      `json:"closed_at,omitempty"`
	Timeline   []AttachedAlert `json:"timeline,omitempty"`
}

func Title(entity string, stages []string) string {
	switch len(stages) {
	case 0, 1:
		if len(stages) == 1 {
			return "Suspicious " + stages[0] + " activity from " + entity
		}
		return "Suspicious activity from " + entity
	default:
		return "Multi-stage attack from " + entity +
			" (" + join(stages, " → ") + ")"
	}
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
