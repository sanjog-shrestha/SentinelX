package normalize

import (
	"encoding/json"
	"fmt"
	"math"
	"sentinelx/internal/event"
	"time"
)

type zeekConn struct {
	TS      float64 `json:"ts"`
	OrigH   string  `json:"id.orig_h"`
	OrigP   int     `json:"id.orig_p"`
	RespH   string  `json:"id.resp_h"`
	RespP   int     `json:"id.resp_p"`
	Proto   string  `json:"proto"`
	Service string  `json:"service"`
}

func ZeekConn(line []byte) (*event.Event, error) {
	var rec zeekConn
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("zeek unmarshal: %w", err)
	}
	if rec.OrigH == "" {
		return nil, nil
	}

	sec, frac := math.Modf(rec.TS)
	occurred := time.Unix(int64(sec), int64(frac*1e9)).UTC()

	svc := rec.Service
	if svc == "" {
		svc = "unknown"
	}
	msg := fmt.Sprintf("connection %s %s:%d -> %s:%d (service %s)",
		rec.Proto, rec.OrigH, rec.OrigP, rec.RespH, rec.RespP, svc)

	return &event.Event{
		EventID:    event.DeterministicID(line),
		Source:     "zeek",
		Category:   "flow",
		Severity:   "info",
		Message:    msg,
		OccurredAt: occurred,
		SrcIP:      rec.OrigH,
		SrcPort:    rec.OrigP,
		DstIP:      rec.RespH,
		DstPort:    rec.RespP,
		Proto:      rec.Proto,
	}, nil
}
