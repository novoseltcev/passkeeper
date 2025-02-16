package server

import (
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is a server configuration.
type Config struct {
	Address        string       `env:"ADDRESS"         env-default:":8080"`
	TrustedProxies []string     `env:"TRUSTED_PROXIES" env-default:""`
	Level          string       `env:"LEVEL"           env-default:"info"`
	DB             DBConfig     `env-prefix:"DB_"`
	JWT            JWTConfig    `env-prefix:"JWT_"`
	Bcrypt         BcryptConfig `env-prefix:"BCRYPT_"`
}

type DBConfig struct {
	Dsn string `env:"DSN"`
}

type JWTConfig struct {
	Secret   string        `env:"SECRET"`
	Lifetime time.Duration `env:"LIFETIME" env-default:"7d"`
}

type BcryptConfig struct {
	Cost int `env:"COST" env-default:"12"`
}

func (cfg *Config) LoadEnv() error {
	return env.Parse(cfg)
}
