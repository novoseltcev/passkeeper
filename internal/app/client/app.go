package client

import (
	"context"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"go.uber.org/zap"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/tui"
)

type App struct {
	cfg *Config
	log *zap.Logger
	api adapters.API
}

func New(cfg *Config, log *zap.Logger, api adapters.API) *App {
	return &App{cfg: cfg, log: log, api: api}
}

func (a *App) Run(ctx context.Context) {
	a.log.Info("Application starting")

	tApp := tview.NewApplication().EnableMouse(true).EnablePaste(true)
	tApp.SetRoot(tui.NewLayout(a.api), true)
	tApp.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return event
	})

	notify := make(chan error)
	go func() {
		notify <- tApp.Run()
		close(notify)
	}()

	doneCh := make(chan struct{})
	go func() { // nolint: contextcheck
		defer close(doneCh)

		select {
		case <-ctx.Done():
			a.log.Info("Interrupted by context")
		case err := <-notify:
			if err == nil {
				return
			}

			a.log.Error("Failed to start application", zap.Error(err))
		}

		tApp.Stop()
	}()

	<-doneCh
	a.log.Info("Application stopped")
}
