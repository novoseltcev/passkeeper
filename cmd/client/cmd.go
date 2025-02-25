package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/app/client"
)

func Cmd() *cobra.Command {
	cfg := &client.Config{}

	cmd := &cobra.Command{
		Use:   "passkeeper",
		Short: "Passkeeper CLI",
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

			app := client.New(cfg, logger, adapters.NewHTTP(http.DefaultClient, cfg.ServerAddress))

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			app.Run(ctx)
		},
	}
	initFlags(cfg, cmd.Flags())

	return cmd
}

// initFlags initializes flags for parsing and help command.
func initFlags(cfg *client.Config, flags *pflag.FlagSet) {
	flags.StringVarP(&cfg.ServerAddress, "address", "a", "http://localhost:8080", "Server address")
	flags.StringVarP(&cfg.Level, "level", "l", "info", "Log level")
}
