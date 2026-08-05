package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"sentinelx/internal/correlate"
	"sentinelx/internal/detect"
)

func (p *Postgres) AttachAlert(ctx context.Context, a detect.Alert, idle time.Duration) (
	*correlate.Incident, bool, bool, error) {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, false, false, err
	}
	defer tx.Rollback(ctx)

	cutoff := a.CreatedAt.Add(-idle)

	var inc correlate.Incident
	var stagesRaw []byte
	err = tx.QueryRow(ctx,
		`SELECT incident_id, entity, title, status, severity, score, stages,
		        alert_count, first_seen, last_seen
		 FROM incidents
		 WHERE entity = $1 AND status = 'open' AND last_seen >= $2
		 ORDER BY id DESC LIMIT 1
		 FOR UPDATE`,
		a.Entity, cutoff,
	).Scan(&inc.IncidentID, &inc.Entity, &inc.Title, &inc.Status, &inc.Severity,
		&inc.Score, &stagesRaw, &inc.AlertCount, &inc.FirstSeen, &inc.LastSeen)

	isNew := false
	if errors.Is(err, pgx.ErrNoRows) {
		isNew = true
		inc = correlate.Incident{
			IncidentID: detect.NewAlertID(a.Entity, a.CreatedAt),
			Entity:     a.Entity,
			Title:      "Suspicious activity from " + a.Entity,
			Status:     "open",
			Severity:   "low",
			FirstSeen:  a.FirstSeen,
			LastSeen:   a.LastSeen,
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (incident_id, entity, title, status, severity,
			                        score, stages, alert_count, first_seen, last_seen)
			 VALUES ($1,$2,$3,'open','low',0,'[]',0,$4,$5)`,
			inc.IncidentID, inc.Entity, inc.Title, inc.FirstSeen, inc.LastSeen); err != nil {
			return nil, false, false, err
		}
	} else if err != nil {
		return nil, false, false, err
	}

	stage := correlate.StageOf(a.RuleID)
	tag, err := tx.Exec(ctx,
		`INSERT INTO incident_alerts (incident_id, alert_id, rule_id, stage, title, severity, occurred_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (incident_id, alert_id) DO NOTHING`,
		inc.IncidentID, a.AlertID, a.RuleID, stage, a.Title, a.Severity, a.LastSeen)
	if err != nil {
		return nil, false, false, err
	}
	if tag.RowsAffected() == 0 && !isNew {
		return &inc, false, true, tx.Commit(ctx)
	}

	rows, err := tx.Query(ctx,
		`SELECT alert_id, rule_id, stage, title, severity, occurred_at
		 FROM incident_alerts WHERE incident_id = $1 ORDER BY occurred_at`,
		inc.IncidentID)
	if err != nil {
		return nil, false, false, err
	}
	timeline := []correlate.AttachedAlert{}
	for rows.Next() {
		var t correlate.AttachedAlert
		var at time.Time
		if err := rows.Scan(&t.AlertID, &t.RuleID, &t.Stage, &t.Title, &t.Severity, &at); err != nil {
			rows.Close()
			return nil, false, false, err
		}
		t.OccurredAt = at.UTC().Format(time.RFC3339)
		timeline = append(timeline, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, false, err
	}

	score, stages := correlate.Score(timeline)
	severity := correlate.SeverityFromScore(score)
	title := correlate.Title(inc.Entity, stages)
	stagesJSON, _ := json.Marshal(stages)

	if err := tx.QueryRow(ctx,
		`UPDATE incidents
		 SET score=$2, severity=$3, stages=$4, title=$5,
		     alert_count=$6, last_seen=GREATEST(last_seen, $7)
		 WHERE incident_id=$1
		 RETURNING first_seen, last_seen`,
		inc.IncidentID, score, severity, stagesJSON, title, len(timeline), a.LastSeen,
	).Scan(&inc.FirstSeen, &inc.LastSeen); err != nil {
		return nil, false, false, err
	}

	inc.Score, inc.Stages, inc.Severity, inc.Title = score, stages, severity, title
	inc.AlertCount, inc.Timeline, inc.Status = len(timeline), timeline, "open"

	return &inc, isNew, false, tx.Commit(ctx)
}

func (p *Postgres) CloseIdle(ctx context.Context, idle time.Duration) ([]correlate.Incident, error) {
	rows, err := p.Pool.Query(ctx,
		`UPDATE incidents SET status='closed', closed_at=now()
		 WHERE status='open' AND last_seen < now() - $1::interval
		 RETURNING incident_id, entity, title, severity, score, alert_count, first_seen, last_seen`,
		idle.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []correlate.Incident{}
	for rows.Next() {
		var i correlate.Incident
		if err := rows.Scan(&i.IncidentID, &i.Entity, &i.Title, &i.Severity,
			&i.Score, &i.AlertCount, &i.FirstSeen, &i.LastSeen); err != nil {
			return nil, err
		}
		i.Status = "closed"
		out = append(out, i)
	}
	return out, rows.Err()
}

func (p *Postgres) ListIncidents(ctx context.Context, limit int) ([]correlate.Incident, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT incident_id, entity, title, status, severity, score, stages,
		        alert_count, first_seen, last_seen, closed_at
		 FROM incidents ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []correlate.Incident{}
	for rows.Next() {
		var i correlate.Incident
		var stagesRaw []byte
		if err := rows.Scan(&i.IncidentID, &i.Entity, &i.Title, &i.Status, &i.Severity,
			&i.Score, &stagesRaw, &i.AlertCount, &i.FirstSeen, &i.LastSeen, &i.ClosedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(stagesRaw, &i.Stages)
		out = append(out, i)
	}
	return out, rows.Err()
}

func (p *Postgres) GetIncident(ctx context.Context, id string) (*correlate.Incident, error) {
	var i correlate.Incident
	var stagesRaw []byte
	err := p.Pool.QueryRow(ctx,
		`SELECT incident_id, entity, title, status, severity, score, stages,
		        alert_count, first_seen, last_seen, closed_at
		 FROM incidents WHERE incident_id = $1`, id,
	).Scan(&i.IncidentID, &i.Entity, &i.Title, &i.Status, &i.Severity, &i.Score,
		&stagesRaw, &i.AlertCount, &i.FirstSeen, &i.LastSeen, &i.ClosedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(stagesRaw, &i.Stages)

	rows, err := p.Pool.Query(ctx,
		`SELECT alert_id, rule_id, stage, title, severity, occurred_at
		 FROM incident_alerts WHERE incident_id=$1 ORDER BY occurred_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t correlate.AttachedAlert
		var at time.Time
		if err := rows.Scan(&t.AlertID, &t.RuleID, &t.Stage, &t.Title, &t.Severity, &at); err != nil {
			return nil, err
		}
		t.OccurredAt = at.UTC().Format(time.RFC3339)
		i.Timeline = append(i.Timeline, t)
	}
	return &i, rows.Err()
}
