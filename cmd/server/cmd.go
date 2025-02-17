package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/novoseltcev/passkeeper/internal/app"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/repo"
	"github.com/novoseltcev/passkeeper/pkg/aes"
	"github.com/novoseltcev/passkeeper/pkg/pwdhash"
)

func Cmd() *cobra.Command {
	cfg := &app.Config{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Passkeeper server",
		Run: func(_ *cobra.Command, _ []string) {
			var err error
			zapCfg := zap.NewProductionConfig()
			zapCfg.Level, err = zap.ParseAtomicLevel(cfg.Level)
			if err != nil {
				log.Fatal("failed to parse log level", zap.Error(err))
			}

			logger, err := zapCfg.Build()
			if err != nil {
				log.Fatal("failed to build logger", zap.Error(err))
			}
			defer logger.Sync() // nolint: errcheck
			defer zap.RedirectStdLog(logger)()

			if err := cfg.LoadEnv(); err != nil {
				logger.Fatal("failed to load environment variables", zap.Error(err))
			}

			logger.Debug("config", zap.Any("cfg", cfg))

			db, err := sqlx.Open("pgx", cfg.DB.Dsn)
			if err != nil {
				logger.Fatal("failed to open connection to database", zap.Error(err), zap.String("dsn", cfg.DB.Dsn))
			}
			defer db.Close()

			hasher := pwdhash.NewBCrypt(cfg.Bcrypt.Cost)

			app := app.New(
				cfg, logger, db,
				repo.NewTokenRepository(db),
				secrets.NewService(repo.NewSecretRepository(db), hasher, aes.New(aes.AES_256_BIT_KEY_LENGTH)),
				user.NewService(repo.NewUserRepository(db), hasher),
			)

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			app.Run(ctx)
		},
	}
	initFlags(cfg, cmd.Flags())

	return cmd
}

// initFlags initializes flags for parsing and help command.
func initFlags(cfg *app.Config, flags *pflag.FlagSet) {
	flags.StringVarP(&cfg.Address, "address", "a", ":8080", "Server address")
	flags.StringVarP(&cfg.Level, "level", "l", "info", "Log level")
}
