package bus

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

const HeartbeatSubject = "sentinelx.heartbeat"

type Heartbeat struct {
	Service string    `json:"service"`
	SentAt  time.Time `json:"sent_at"`
}

func Connect(url, name string) (*nats.Conn, error) {
	return nats.Connect(url,
		nats.Name(name),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
}

func PublishHeartbeat(nc *nats.Conn, service string) error {
	payload, err := json.Marshal(Heartbeat{Service: service, SentAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	return nc.Publish(HeartbeatSubject, payload)
}

func StartHeartbeat(ctx context.Context, nc *nats.Conn, service string, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()

		_ = PublishHeartbeat(nc, service)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := PublishHeartbeat(nc, service); err != nil {
					slog.Warn("heartbeat publish failed", "service", service, "err", err)
				}
			}
		}
	}()
}
