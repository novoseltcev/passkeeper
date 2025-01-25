package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/novoseltcev/passkeeper/internal/server"
)

func Cmd() *cobra.Command {
	cfg := &server.Config{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Passkeeper server",
		Run: func(_ *cobra.Command, _ []string) {
			logger := logrus.New()

			lvl, err := logrus.ParseLevel(cfg.Level)
			if err != nil {
				logger.WithError(err).Panic("failed to parse log level")
			}

			logrus.SetLevel(lvl)

			if cfg.DatabaseDsn == "" {
				logger.Fatal("database connection string is empty")
			}

			db, err := sqlx.Open("pgx", cfg.DatabaseDsn)
			if err != nil {
				logger.WithError(err).Panic("failed to open connection to database")
			}
			defer db.Close()

			app := server.NewApp(cfg, logger, db)

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			app.Run(ctx)
		},
	}
	initFlags(cfg, cmd.Flags())

	return cmd
}

// initFlags initializes flags for parsing and help command.
func initFlags(cfg *server.Config, flags *pflag.FlagSet) {
	flags.StringVarP(&cfg.Address, "address", "a", ":8080", "Server address")
	flags.StringVarP(&cfg.Level, "level", "l", "info", "Log level")
}
