package correlate

import "sentinelx/internal/detect"

const (
	StageRecon      = "recon"
	StageExploit    = "exploitation"
	StageCredential = "credential-access"
	StageImpact     = "impact"
)

var stageRank = map[string]int{
	StageRecon:      1,
	StageExploit:    2,
	StageCredential: 3,
	StageImpact:     4,
}

var ruleStage = map[string]string{
	"port-scan":           StageRecon,
	"asset-new-host":      StageRecon,
	"web-attack-burst":    StageExploit,
	"high-severity-burst": StageExploit,
	"auth-brute-force":    StageCredential,
}

func StageOf(ruleID string) string {
	if s, ok := ruleStage[ruleID]; ok {
		return s
	}
	return StageExploit // unknown rules default to the middle
}

var severityPoints = map[string]int{
	"info": 1, "low": 2, "medium": 4, "high": 7, "critical": 10,
}

func Score(alerts []AttachedAlert) (int, []string) {
	total := 0
	seen := map[string]bool{}
	maxRank := 0

	for _, a := range alerts {
		pts := severityPoints[a.Severity]
		if pts == 0 {
			pts = 2
		}
		total += pts

		if !seen[a.Stage] {
			seen[a.Stage] = true
			total += 12 // each NEW stage is worth more than several alerts
		}
		if r := stageRank[a.Stage]; r > maxRank {
			maxRank = r
		}
	}

	total += maxRank * 5

	stages := []string{}
	for _, s := range []string{StageRecon, StageExploit, StageCredential, StageImpact} {
		if seen[s] {
			stages = append(stages, s)
		}
	}
	return total, stages
}

func SeverityFromScore(score int) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 35:
		return "high"
	case score >= 18:
		return "medium"
	default:
		return "low"
	}
}

type AttachedAlert struct {
	AlertID    string `json:"alert_id"`
	RuleID     string `json:"rule_id"`
	Stage      string `json:"stage"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	OccurredAt string `json:"occurred_at"`
}

func FromAlert(a detect.Alert) AttachedAlert {
	return AttachedAlert{
		AlertID:  a.AlertID,
		RuleID:   a.RuleID,
		Stage:    StageOf(a.RuleID),
		Title:    a.Title,
		Severity: a.Severity,
	}
}
