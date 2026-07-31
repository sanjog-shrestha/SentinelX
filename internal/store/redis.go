package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const servicesKey = "sentinelx:services"

type Redis struct {
	Client *redis.Client
}

func NewRedis(addr string) *Redis {
	return &Redis{Client: redis.NewClient(&redis.Options{Addr: addr})}
}

func (r *Redis) Ping(ctx context.Context) error { return r.Client.Ping(ctx).Err() }

func (r *Redis) RecordHeartbeat(ctx context.Context, service string, at time.Time) error {
	return r.Client.HSet(ctx, servicesKey, service, at.UTC().Format(time.RFC3339)).Err()
}

func (r *Redis) ServiceStatuses(ctx context.Context, staleAfter time.Duration) (map[string]any, error) {
	raw, err := r.Client.HGetAll(ctx, servicesKey).Result()
	if err != nil {
		return nil, err
	}

	out := map[string]any{}
	now := time.Now().UTC()
	for name, ts := range raw {
		status := "unknown"
		if last, err := time.Parse(time.RFC3339, ts); err == nil {
			if now.Sub(last) <= staleAfter {
				status = "alive"
			} else {
				status = "stale"
			}
		}
		out[name] = map[string]any{"last_heartbeat": ts, "status": status}
	}
	return out, nil
}
