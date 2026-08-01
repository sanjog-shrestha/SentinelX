package event

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Event struct {
	EventID    string    `json:"event_id"`
	Source     string    `json:"source"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	OccurredAt time.Time `json:"occurred_at"`

	DBID      int64     `json:"db_id,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
