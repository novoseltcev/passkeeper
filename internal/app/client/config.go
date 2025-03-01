package client

import "github.com/caarlos0/env/v11"

// Config is a server configuration.
type Config struct {
	ServerAddress string `env:"SERVER_ADDRESS"`
	Level         string `env:"LEVEL"`
}

func (cfg *Config) LoadEnv() error {
	return env.Parse(cfg)
}
