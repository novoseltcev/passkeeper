package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/srv"
	v1 "github.com/novoseltcev/passkeeper/internal/controllers/http/v1"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/middleware"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
	"github.com/novoseltcev/passkeeper/pkg/httpserver"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

const (
	defaultGracefulShutdownTimeout = 5 * time.Second
)

type App struct {
	cfg           *Config
	log           *zap.Logger
	db            *sqlx.DB
	jwtStorager   jwtmanager.TokenStorager
	secretService secrets.Service
	userService   user.Service
}

func NewApp(
	cfg *Config,
	log *zap.Logger,
	db *sqlx.DB,
	jwtStorager jwtmanager.TokenStorager,
	secretService secrets.Service,
	userService user.Service,
) *App {
	return &App{
		cfg:           cfg,
		log:           log,
		db:            db,
		jwtStorager:   jwtStorager,
		secretService: secretService,
		userService:   userService,
	}
}

func (a *App) Run(ctx context.Context) {
	a.log.Info("Server starting")

	rootHandler, err := a.getRootHandler()
	if err != nil {
		a.log.Error("Failed to create root handler", zap.Error(err))

		return
	}

	srv := httpserver.New(rootHandler, httpserver.WithAddr(a.cfg.Address))
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
	a.log.Info("Server stopped")
}

func (a *App) getRootHandler() (http.Handler, error) {
	root := gin.New()
	if err := root.SetTrustedProxies(a.cfg.TrustedProxies); err != nil {
		return nil, err
	}

	root.Use(
		ginzap.Ginzap(a.log, time.RFC3339, false),
		gin.Recovery(),
	)

	jwt := jwtmanager.New(a.cfg.JWT.Secret,
		jwtmanager.WithIssuer("PassKeeper"),
		jwtmanager.WithAlgorithm(jwt.SigningMethodHS512),
		jwtmanager.WithExpiration(a.cfg.JWT.Lifetime),
		jwtmanager.WithTokenStorage(a.jwtStorager),
	)

	srv.AddRoutes(root.Group("/srv"))
	v1.AddRoutes(root.Group("/v1"), jwt, middleware.JWT(jwt, auth.IdentityKey), a.secretService, a.userService)

	return root.Handler(), nil
}
