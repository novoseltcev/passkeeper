package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/novoseltcev/passkeeper/pkg/httpserver"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

const (
	defaultGracefulShutdownTimeout = 5 * time.Second
)

type App struct {
	cfg         *Config
	log         *zap.Logger
	db          *sqlx.DB
	jwtStorager jwtmanager.TokenStorager
}

func NewApp(cfg *Config, log *zap.Logger, db *sqlx.DB, jwtStorager jwtmanager.TokenStorager) *App {
	return &App{
		cfg:         cfg,
		log:         log,
		db:          db,
		jwtStorager: jwtStorager,
	}
}

func (a *App) Run(ctx context.Context) {
	a.log.Info("Server starting")

	// TODO@novoseltcev: add router
	srv := httpserver.New(nil, httpserver.WithAddr(a.config.Address))
	go srv.Run()

	a.log.Info("Server started")

	doneCh := make(chan struct{})
	go func() { // nolint: contextcheck
		defer close(doneCh)

		select {
		case <-ctx.Done():
			a.log.Info("Interrupted by context")
		case err := <-srv.Notify():
			if !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("Failed to listen and serve", zap.Error(err))
			}
		}
		a.log.Info("Shutting down, pless Ctrl+C to force")

		timeoutCtx, cancel := context.WithTimeout(context.Background(), defaultGracefulShutdownTimeout)
		defer cancel()

		g, ctx := errgroup.WithContext(timeoutCtx)
		g.Go(func() error {
			return srv.Shutdown(ctx)
		})

		if err := g.Wait(); err != nil {
			a.log.Error("Failed to shutdown", zap.Error(err))
		}
	}()

	<-doneCh
	a.logger.Info("Server stopped")
}
