package store

import (
	"context"
	"encoding/json"
	"errors"
	"sentinelx/internal/detect"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) InsertAlert(ctx context.Context, a *detect.Alert) (bool, error) {
	evidence, err := json.Marshal(a.Evidence)
	if err != nil {
		return false, err
	}
	var id int64
	err = p.Pool.QueryRow(ctx,
		`INSERT INTO alerts (alert_id, rule_id, title, severity, entity,
			match_count, first_seen, last_seen, evidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (alert_id) DO NOTHING
		RETURNING id`,
		a.AlertID, a.RuleID, a.Title, a.Severity, a.Entity,
		a.Count, a.FirstSeen, a.LastSeen, evidence,
	).Scan(&id)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (p *Postgres) ListAlerts(ctx context.Context, limit int) ([]detect.Alert, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT alert_id, rule_id, title, severity, entity,
			match_count, first_seen, last_seen, evidence, created_at 
		FROM alerts ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := []detect.Alert{}
	for rows.Next() {
		var a detect.Alert
		var evidence []byte
		if err := rows.Scan(&a.AlertID, &a.RuleID, &a.Title, &a.Severity, &a.Entity,
			&a.Count, &a.FirstSeen, &a.LastSeen, &evidence, &a.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidence, &a.Evidence)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}
