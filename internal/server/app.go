package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"

	"github.com/novoseltcev/passkeeper/pkg/grpcserver"
)

type App struct {
	config *Config
	logger *logrus.Logger
	db     *sqlx.DB
}

func NewApp(config *Config, logger *logrus.Logger, db *sqlx.DB) *App {
	return &App{
		config: config,
		logger: logger,
		db:     db,
	}
}

func (a *App) Run(ctx context.Context) {
	a.logger.Info("Server starting")

	srv := grpcserver.New(a.config.Address)
	// TODO@novoseltcev: register grpc-service
	go srv.Run()

	a.logger.Info("Server started")

	doneCh := make(chan struct{})
	go func() { // nolint: contextcheck
		defer close(doneCh)

		select {
		case <-ctx.Done():
			a.logger.Info("Interrupted by context")
		case err := <-srv.Notify():
			if !errors.Is(err, http.ErrServerClosed) {
				a.logger.WithError(err).Error("Failed to listen and serve")
			}
		}
		a.logger.Info("Shutting down")

		if err := srv.Shutdown(); err != nil {
			a.logger.WithError(err).Error("Failed to shutdown")
		}
	}()

	<-doneCh
	a.logger.Info("Server stopped")
}
