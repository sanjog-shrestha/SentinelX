package asset

import "time"

type Asset struct {
	Host      string    `json:"host"`
	Hostname  string    `json:"hostname"`
	Proto     string    `json:"proto"`
	Port      int       `json:"port"`
	Service   string    `json:"service"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func (a Asset) Key() string {
	return a.Host + "|" + a.Proto + "|" + itoa(a.Port)
}

const (
	KindNewHost    = "new_host"
	KindNewPort    = "new_port"
	KindPortClosed = "port_closed"
	KindService    = "service_changed"
)

type Change struct {
	Kind       string    `json:"kind"`
	Host       string    `json:"host"`
	Proto      string    `json:"proto"`
	Port       int       `json:"port"`
	Detail     string    `json:"detail"`
	DetectedAt time.Time `json:"detected_at"`
}
