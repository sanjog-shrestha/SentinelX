package normalize

import (
	"encoding/json"
	"fmt"
	"sentinelx/internal/event"
	"time"
)

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

func Suricata(line []byte) (*event.Event, error) {
	var rec eveRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("suricata unmarshal: %w", err)
	}
	if rec.EventType != "alert" || rec.Alert == nil {
		return nil, nil
	}

	severity := "low"
	switch rec.Alert.Severity {
	case 1:
		severity = "high"
	case 2:
		severity = "medium"
	}

	occurred, err := time.Parse("2006-01-02T15:04:05.999999-0700", rec.Timestamp)
	if err != nil {
		occurred = time.Now().UTC()
	}

	return &event.Event{
		EventID:    event.DeterministicID(line),
		Source:     "suricata",
		Category:   rec.Alert.Category,
		Severity:   severity,
		Message:    rec.Alert.Signature,
		OccurredAt: occurred.UTC(),
		SrcIP:      rec.SrcIP,
		SrcPort:    rec.SrcPort,
		DstIP:      rec.DestIP,
		DstPort:    rec.DestPort,
		Proto:      rec.Proto,
	}, nil
}
