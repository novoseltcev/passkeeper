package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/novoseltcev/passkeeper/pkg/httpserver"
)

const (
	defaultGracefulShutdownTimeout = 5 * time.Second
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

	// TODO@novoseltcev: add router
	srv := httpserver.New(nil, httpserver.WithAddr(a.config.Address))
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

		timeoutCtx, cancel := context.WithTimeout(context.Background(), defaultGracefulShutdownTimeout)
		defer cancel()

		g, ctx := errgroup.WithContext(timeoutCtx)
		g.Go(func() error {
			return srv.Shutdown(ctx)
		})

		if err := g.Wait(); err != nil {
			a.logger.WithError(err).Error("Failed to shutdown")
		}
	}()

	<-doneCh
	a.logger.Info("Server stopped")
}
