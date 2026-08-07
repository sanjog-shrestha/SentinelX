package ai

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelx/internal/correlate"
	"sentinelx/internal/event"
)

const SystemPrompt = `You are a SOC (Security Operations Center) analyst assistant.
You will be given evidence collected by an automated security platform.

Rules you must follow:
1. Base every statement ONLY on the evidence provided. Never invent IP addresses,
   hostnames, usernames, ports, or timestamps that do not appear in the evidence.
2. If the evidence is weak or ambiguous, say so plainly and lower your confidence.
3. Be concise and factual. No marketing language, no speculation presented as fact.
4. Recommendations must be concrete actions a human operator can take.
5. Respond with a single JSON object and nothing else.
6. Threat intelligence matches are claims made by third-party feeds, not proof
   of compromise. Treat them as supporting evidence and name the source.`

type Report struct {
	Summary                 string   `json:"summary"`
	Assessment              string   `json:"assessment"`
	Confidence              string   `json:"confidence"`
	FalsePositiveLikelihood string   `json:"false_positive_likelihood"`
	Recommendations         []string `json:"recommendations"`
}

const schemaBlock = `Respond with exactly this JSON shape:
{
  "summary": "2-3 sentences describing what happened",
  "assessment": "your judgement of how serious this is and why",
  "confidence": "low|medium|high",
  "false_positive_likelihood": "low|medium|high",
  "recommendations": ["action 1", "action 2"]
}`

func Build(inc correlate.Incident, events []event.Event) string {
	var b strings.Builder

	fmt.Fprintf(&b, "INCIDENT\n")
	fmt.Fprintf(&b, "  id: %s\n", inc.IncidentID)
	fmt.Fprintf(&b, "  entity (source): %s\n", inc.Entity)
	fmt.Fprintf(&b, "  rule-based severity: %s (score %d)\n", inc.Severity, inc.Score)
	fmt.Fprintf(&b, "  attack stages observed: %s\n", strings.Join(inc.Stages, ", "))
	fmt.Fprintf(&b, "  window: %s to %s\n",
		inc.FirstSeen.Format("2006-01-02 15:04:05Z"),
		inc.LastSeen.Format("2006-01-02 15:04:05Z"))
	fmt.Fprintf(&b, "  alerts in incident: %d\n\n", inc.AlertCount)

	b.WriteString("DETECTION TIMELINE (produced by deterministic rules)\n")
	for i, t := range inc.Timeline {
		if i >= 20 {
			fmt.Fprintf(&b, "  ... %d more alerts omitted\n", len(inc.Timeline)-20)
			break
		}
		fmt.Fprintf(&b, "  %s | stage=%s severity=%s | %s\n",
			t.OccurredAt, t.Stage, t.Severity, t.Title)
	}

	b.WriteString("\nSUPPORTING RAW EVENTS (sample from sensors)\n")
	for i, e := range events {
		if i >= 25 {
			fmt.Fprintf(&b, "  ... %d more events omitted\n", len(events)-25)
			break
		}
		// NEW in Phase 8: surface the intel verdict inline so the model
		// can reason about it instead of guessing from the IP alone.
		flag := ""
		if e.IntelMatch {
			flag = fmt.Sprintf(" [THREAT INTEL: listed by %s as %s, confidence %d]",
				e.IntelSource, e.IntelCategory, e.IntelConfidence)
		}
		fmt.Fprintf(&b, "  %s | %s | %s->%s:%d %s | %s%s\n",
			e.OccurredAt.Format("15:04:05"), e.Source,
			e.SrcIP, e.DstIP, e.DstPort, e.Proto, truncate(e.Message, 90), flag)
	}

	b.WriteString("\n")
	b.WriteString(schemaBlock)
	return b.String()
}

func Parse(raw string) (*Report, error) {
	var r Report
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("model returned invalid JSON: %w", err)
	}
	if strings.TrimSpace(r.Summary) == "" {
		return nil, fmt.Errorf("model returned empty summary")
	}
	r.Confidence = normalizeLevel(r.Confidence)
	r.FalsePositiveLikelihood = normalizeLevel(r.FalsePositiveLikelihood)
	if r.Recommendations == nil {
		r.Recommendations = []string{}
	}
	return &r, nil
}

func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return "low"
	case "medium", "moderate", "med":
		return "medium"
	case "high":
		return "high"
	default:
		return "unknown"
	}
}

func Grounded(r *Report, entity string) bool {
	blob := strings.ToLower(r.Summary + " " + r.Assessment)
	return strings.Contains(blob, strings.ToLower(entity))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
