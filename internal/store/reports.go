package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"sentinelx/internal/ai"
	"sentinelx/internal/event"
)

func (p *Postgres) EventsForEntity(ctx context.Context, entity string, since time.Time, limit int) ([]event.Event, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT id, event_id, source, category, severity, message,
		        occurred_at, created_at, src_ip, src_port, dst_ip, dst_port, proto
		 FROM events
		 WHERE src_ip = $1 AND occurred_at >= $2
		 ORDER BY occurred_at DESC LIMIT $3`,
		entity, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []event.Event{}
	for rows.Next() {
		var e event.Event
		if err := rows.Scan(&e.DBID, &e.EventID, &e.Source, &e.Category, &e.Severity,
			&e.Message, &e.OccurredAt, &e.CreatedAt, &e.SrcIP, &e.SrcPort,
			&e.DstIP, &e.DstPort, &e.Proto); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type StoredReport struct {
	IncidentID              string    `json:"incident_id"`
	Model                   string    `json:"model"`
	Summary                 string    `json:"summary"`
	Assessment              string    `json:"assessment"`
	Confidence              string    `json:"confidence"`
	FalsePositiveLikelihood string    `json:"false_positive_likelihood"`
	Recommendations         []string  `json:"recommendations"`
	ScoreAtGeneration       int       `json:"score_at_generation"`
	GeneratedAt             time.Time `json:"generated_at"`
}

func (p *Postgres) UpsertReport(ctx context.Context, incidentID, model string, r *ai.Report, score int) error {
	recs, _ := json.Marshal(r.Recommendations)
	_, err := p.Pool.Exec(ctx,
		`INSERT INTO incident_reports (incident_id, model, summary, assessment,
		     confidence, false_positive_likelihood, recommendations,
		     score_at_generation, generated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		 ON CONFLICT (incident_id) DO UPDATE
		 SET model=EXCLUDED.model, summary=EXCLUDED.summary,
		     assessment=EXCLUDED.assessment, confidence=EXCLUDED.confidence,
		     false_positive_likelihood=EXCLUDED.false_positive_likelihood,
		     recommendations=EXCLUDED.recommendations,
		     score_at_generation=EXCLUDED.score_at_generation,
		     generated_at=now()`,
		incidentID, model, r.Summary, r.Assessment, r.Confidence,
		r.FalsePositiveLikelihood, recs, score)
	return err
}

func (p *Postgres) GetReport(ctx context.Context, incidentID string) (*StoredReport, error) {
	var s StoredReport
	var recs []byte
	err := p.Pool.QueryRow(ctx,
		`SELECT incident_id, model, summary, assessment, confidence,
		        false_positive_likelihood, recommendations, score_at_generation, generated_at
		 FROM incident_reports WHERE incident_id = $1`, incidentID,
	).Scan(&s.IncidentID, &s.Model, &s.Summary, &s.Assessment, &s.Confidence,
		&s.FalsePositiveLikelihood, &recs, &s.ScoreAtGeneration, &s.GeneratedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(recs, &s.Recommendations)
	return &s, nil
}
