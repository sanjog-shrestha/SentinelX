package intel

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyIPs   = "sentinelx:intel:ips"
	keyCIDRs = "sentinelx:intel:cidrs"
	keyTmpIP = "sentinelx:intel:ips:tmp"
	keyTmpCI = "sentinelx:intel:cidrs:tmp"
)

type meta struct {
	Source     string `json:"s"`
	Category   string `json:"c"`
	Confidence int    `json:"n"`
}

func Publish(ctx context.Context, rdb *redis.Client, indicators []Indicator) error {
	pipe := rdb.Pipeline()
	pipe.Del(ctx, keyTmpIP, keyTmpCI)

	ips := map[string]any{}
	cidrs := []any{}
	for _, ind := range indicators {
		if ind.Kind == KindCIDR {
			cidrs = append(cidrs, ind.Indicator)
			continue
		}
		blob, _ := json.Marshal(meta{ind.Source, ind.Category, ind.Confidence})
		ips[ind.Indicator] = string(blob)
	}

	if len(ips) > 0 {
		pipe.HSet(ctx, keyTmpIP, ips)
	}
	if len(cidrs) > 0 {
		pipe.SAdd(ctx, keyTmpCI, cidrs...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	swap := rdb.Pipeline()
	if len(ips) > 0 {
		swap.Rename(ctx, keyTmpIP, keyIPs)
	}
	if len(cidrs) > 0 {
		swap.Rename(ctx, keyTmpCI, keyCIDRs)
	}
	_, err := swap.Exec(ctx)
	return err
}

type Lookup struct {
	rdb *redis.Client

	mu       sync.RWMutex
	prefixes []netip.Prefix
}

func NewLookup(rdb *redis.Client) *Lookup {
	return &Lookup{rdb: rdb}
}

func (l *Lookup) RefreshCIDRs(ctx context.Context) error {
	vals, err := l.rdb.SMembers(ctx, keyCIDRs).Result()
	if err != nil {
		return err
	}
	prefixes := make([]netip.Prefix, 0, len(vals))
	for _, v := range vals {
		if p, err := netip.ParsePrefix(v); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	l.mu.Lock()
	l.prefixes = prefixes
	l.mu.Unlock()
	return nil
}

func (l *Lookup) Check(ctx context.Context, ip string) Match {
	if ip == "" {
		return Match{}
	}

	if raw, err := l.rdb.HGet(ctx, keyIPs, ip).Result(); err == nil {
		var m meta
		if json.Unmarshal([]byte(raw), &m) == nil {
			return Match{
				Matched: true, Indicator: ip,
				Source: m.Source, Category: m.Category, Confidence: m.Confidence,
			}
		}
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Match{}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return Match{
				Matched: true, Indicator: p.String(),
				Source: "cidr-feed", Category: "network-block", Confidence: 70,
			}
		}
	}
	return Match{}
}

func (l *Lookup) StartRefresh(ctx context.Context, every time.Duration) {
	go func() {
		_ = l.RefreshCIDRs(ctx)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = l.RefreshCIDRs(ctx)
			}
		}
	}()
}
