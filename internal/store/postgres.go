package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	ID        int64     `json:"id"`
	Source    string    `json:"source"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

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

func (p *Postgres) InsertEvent(ctx context.Context, e *Event) error {
	return p.Pool.QueryRow(ctx,
		`INSERT INTO events (source, category, severity, message)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`,
		e.Source, e.Category, e.Severity, e.Message,
	).Scan(&e.ID, &e.CreatedAt)
}

func (p *Postgres) ListEvents(ctx context.Context, limit int) ([]Event, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT id, source, category, severity, message, created_at
		FROM events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Source, &e.Category, &e.Severity, &e.Message, &e.CreatedAt); err != nil {
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
