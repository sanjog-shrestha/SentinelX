package config

import (
	"cmp"
	"os"
)

type Config struct {
	ServiceName string
	HTTPAddr    string
	PostgresURL string
	RedisAddr   string
	NATSURL     string
	APIBaseURL  string
}

func Load(serviceName, defaultHTTPAddr string) Config {
	return Config{
		ServiceName: serviceName,
		HTTPAddr:    env("HTTP_ADDR", defaultHTTPAddr),
		PostgresURL: env("POSTGRES_URL", "postgres://sentinelx:sentinelx_dev@localhost:5432/sentinelx?sslmode=disable"),
		RedisAddr:   env("REDIS_ADDR", "localhost:6379"),
		NATSURL:     env("NATS_URL", "nats://localhost:4222"),
		APIBaseURL:  env("API_BASE_URL", "http://localhost:8080"),
	}
}

func env(key, fallback string) string {
	return cmp.Or(os.Getenv(key), fallback)
}
