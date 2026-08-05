package config

import (
	"cmp"
	"os"
	"time"
)

type Config struct {
	ServiceName         string
	HTTPAddr            string
	PostgresURL         string
	RedisAddr           string
	NATSURL             string
	APIBaseURL          string
	SuricataEve         string
	ZeekDir             string
	Simulate            bool
	ScanTargets         string
	ScanInterval        time.Duration
	ScanTimeout         time.Duration
	IncidentIdleTimeout time.Duration
}

func Load(serviceName, defaultHTTPAddr string) Config {
	return Config{
		ServiceName:         serviceName,
		HTTPAddr:            env("HTTP_ADDR", defaultHTTPAddr),
		PostgresURL:         env("POSTGRES_URL", "postgres://sentinelx:sentinelx_dev@localhost:5432/sentinelx?sslmode=disable"),
		RedisAddr:           env("REDIS_ADDR", "localhost:6379"),
		NATSURL:             env("NATS_URL", "nats://localhost:4222"),
		APIBaseURL:          env("API_BASE_URL", "http://localhost:8080"),
		SuricataEve:         env("SURICATA_EVE", ""),
		ZeekDir:             env("ZEEK_DIR", ""),
		Simulate:            env("SIMULATE", "false") == "true",
		ScanTargets:         env("SCAN_TARGETS", "172.28.0.0/24"),
		ScanInterval:        envDuration("SCAN_INTERVAL", 5*time.Minute),
		ScanTimeout:         envDuration("SCAN_TIMEOUT", 4*time.Minute),
		IncidentIdleTimeout: envDuration("INCIDENT_IDLE_TIMEOUT", 15*time.Minute),
	}
}

func env(key, fallback string) string {
	return cmp.Or(os.Getenv(key), fallback)
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
