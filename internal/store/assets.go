package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"sentinelx/internal/asset"
)

func (p *Postgres) OpenAssets(ctx context.Context) ([]asset.Asset, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT host, hostname, proto, port, service, state, first_seen, last_seen
		 FROM assets WHERE state = 'open' ORDER BY host, port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []asset.Asset{}
	for rows.Next() {
		var a asset.Asset
		if err := rows.Scan(&a.Host, &a.Hostname, &a.Proto, &a.Port,
			&a.Service, &a.State, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) ApplyScan(ctx context.Context, found []asset.Asset, at time.Time) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, a := range found {
		if _, err := tx.Exec(ctx,
			`INSERT INTO assets (host, hostname, proto, port, service, state, first_seen, last_seen)
			 VALUES ($1,$2,$3,$4,$5,'open',$6,$6)
			 ON CONFLICT (host, proto, port) DO UPDATE
			 SET state = 'open', service = EXCLUDED.service,
			     hostname = EXCLUDED.hostname, last_seen = EXCLUDED.last_seen`,
			a.Host, a.Hostname, a.Proto, a.Port, a.Service, at); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE assets SET state = 'closed' WHERE state = 'open' AND last_seen < $1`, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) InsertChange(ctx context.Context, changeID string, c asset.Change) (bool, error) {
	var id int64
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO asset_changes (change_id, kind, host, proto, port, detail, detected_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (change_id) DO NOTHING
		 RETURNING id`,
		changeID, c.Kind, c.Host, c.Proto, c.Port, c.Detail, c.DetectedAt,
	).Scan(&id)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (p *Postgres) ListAssets(ctx context.Context, limit int) ([]asset.Asset, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT host, hostname, proto, port, service, state, first_seen, last_seen
		 FROM assets ORDER BY host, port LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []asset.Asset{}
	for rows.Next() {
		var a asset.Asset
		if err := rows.Scan(&a.Host, &a.Hostname, &a.Proto, &a.Port,
			&a.Service, &a.State, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) ListChanges(ctx context.Context, limit int) ([]asset.Change, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT kind, host, proto, port, detail, detected_at
		 FROM asset_changes ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []asset.Change{}
	for rows.Next() {
		var c asset.Change
		if err := rows.Scan(&c.Kind, &c.Host, &c.Proto, &c.Port, &c.Detail, &c.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
