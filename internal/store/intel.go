package store

import (
	"context"
	"time"

	"sentinelx/internal/intel"
)

func (p *Postgres) UpsertIndicators(ctx context.Context, list []intel.Indicator) (int, error) {
	if len(list) == 0 {
		return 0, nil
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	for _, i := range list {
		if _, err := tx.Exec(ctx,
			`INSERT INTO indicators (indicator, kind, source, category, confidence, last_seen, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (indicator, source) DO UPDATE
			 SET last_seen = EXCLUDED.last_seen,
			     expires_at = EXCLUDED.expires_at,
			     category = EXCLUDED.category,
			     confidence = EXCLUDED.confidence`,
			i.Indicator, i.Kind, i.Source, i.Category, i.Confidence,
			i.LastSeen, i.ExpiresAt); err != nil {
			return 0, err
		}
	}
	return len(list), tx.Commit(ctx)
}

func (p *Postgres) ActiveIndicators(ctx context.Context) ([]intel.Indicator, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT indicator, kind, source, category, confidence, first_seen, last_seen, expires_at
		 FROM indicators WHERE expires_at > now()
		 ORDER BY confidence ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []intel.Indicator{}
	for rows.Next() {
		var i intel.Indicator
		if err := rows.Scan(&i.Indicator, &i.Kind, &i.Source, &i.Category,
			&i.Confidence, &i.FirstSeen, &i.LastSeen, &i.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (p *Postgres) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := p.Pool.Exec(ctx, `DELETE FROM indicators WHERE expires_at < now() - interval '7 days'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) AddCustomIndicator(ctx context.Context, value, category string, confidence int, ttl time.Duration) error {
	kind := intel.KindIP
	if len(value) > 0 && contains(value, '/') {
		kind = intel.KindCIDR
	}
	now := time.Now().UTC()
	_, err := p.Pool.Exec(ctx,
		`INSERT INTO indicators (indicator, kind, source, category, confidence, last_seen, expires_at)
		 VALUES ($1,$2,'manual',$3,$4,$5,$6)
		 ON CONFLICT (indicator, source) DO UPDATE
		 SET category=EXCLUDED.category, confidence=EXCLUDED.confidence,
		     last_seen=EXCLUDED.last_seen, expires_at=EXCLUDED.expires_at`,
		value, kind, category, confidence, now, now.Add(ttl))
	return err
}

func (p *Postgres) IndicatorStats(ctx context.Context) (map[string]any, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT source, count(*) FROM indicators WHERE expires_at > now() GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bySource := map[string]int{}
	total := 0
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		bySource[s] = n
		total += n
	}
	return map[string]any{"total_active": total, "by_source": bySource}, rows.Err()
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
