package bus

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	StreamEvents     = "EVENTS"
	SubjectEventsRaw = "sentinelx.events.raw"
	SubjectEventsDLQ = "sentinelx.events.dlq"
	SubjectAlerts    = "sentinelx.alerts.detected"
	SubjectIncidents = "sentinelx.incidents.updated"
)

func NewJetStream(ctx context.Context, nc *nats.Conn) (jetstream.JetStream, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     StreamEvents,
		Subjects: []string{"sentinelx.events.>", "sentinelx.alerts.>", "sentinelx.incidents.>"},
		Storage:  jetstream.FileStorage,
		MaxAge:   24 * time.Hour,
	})
	return js, err
}
