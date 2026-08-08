package store

import (
	"context"
	"errors"
	"sentinelx/internal/event"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	Pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Postgres{Pool: pool}, nil
}

func (p *Postgres) Ping(ctx context.Context) error { return p.Pool.Ping(ctx) }

func (p *Postgres) InsertEvent(ctx context.Context, e *event.Event) (bool, error) {
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO events (
		     event_id, source, category, severity, message, occurred_at,
		     src_ip, src_port, dst_ip, dst_port, proto,
		     intel_match, intel_source, intel_category, intel_confidence,
		     container, process, os_user)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id, created_at`,
		e.EventID, e.Source, e.Category, e.Severity, e.Message, e.OccurredAt,
		e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto,
		e.IntelMatch, e.IntelSource, e.IntelCategory, e.IntelConfidence,
		e.Container, e.Process, e.OSUser,
	).Scan(&e.DBID, &e.CreatedAt)

	// DO NOTHING + RETURNING yields no row on conflict — that's how we
	// detect a duplicate delivery.
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (p *Postgres) ListEvents(ctx context.Context, limit int) ([]event.Event, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT id, event_id, source, category, severity, message,
		        occurred_at, created_at,
		        src_ip, src_port, dst_ip, dst_port, proto,
		        intel_match, intel_source, intel_category, intel_confidence,
		        container, process, os_user
		 FROM events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []event.Event{}
	for rows.Next() {
		var e event.Event
		// Scan maps by POSITION, not name — this order must match the
		// SELECT list exactly or you'll silently load an IP into a message.
		if err := rows.Scan(
			&e.DBID, &e.EventID, &e.Source, &e.Category, &e.Severity, &e.Message,
			&e.OccurredAt, &e.CreatedAt,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.IntelMatch, &e.IntelSource, &e.IntelCategory, &e.IntelConfidence,
			&e.Container, &e.Process, &e.OSUser); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (p *Postgres) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	err := p.Pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n)
	return n, err
}
