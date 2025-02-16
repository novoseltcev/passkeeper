package server

import (
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is a server configuration.
type Config struct {
	Address        string       `env:"ADDRESS"`
	Level          string       `env:"LEVEL"`
	TrustedProxies []string     `env:"TRUSTED_PROXIES"`
	DB             DBConfig     `envPrefix:"DB_"`
	JWT            JWTConfig    `envPrefix:"JWT_"`
	Bcrypt         BcryptConfig `envPrefix:"BCRYPT_"`
}

type DBConfig struct {
	Dsn string `env:"DSN,required"`
}

type JWTConfig struct {
	Secret   string        `env:"SECRET,required"`
	Lifetime time.Duration `env:"LIFETIME"        envDefault:"24h"`
}

type BcryptConfig struct {
	Cost int `env:"COST" envDefault:"12"`
}

func (cfg *Config) LoadEnv() error {
	return env.Parse(cfg)
}
