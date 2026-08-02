package event

import (
	"crypto/rand"
	"crypto/sha256"
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

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`
}

func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func DeterministicID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}
