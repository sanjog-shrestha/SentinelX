package intel

import "time"

type Indicator struct {
	Indicator  string    `json:"indicator"`
	Kind       string    `json:"kind"`
	Source     string    `json:"source"`
	Category   string    `json:"category"`
	Confidence int       `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Match struct {
	Matched    bool   `json:"matched"`
	Indicator  string `json:"indicator,omitempty"`
	Source     string `json:"source,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
}

const (
	KindIP   = "ip"
	KindCIDR = "cidr"
)
