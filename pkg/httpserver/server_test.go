package httpserver_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/novoseltcev/passkeeper/pkg/httpserver"
)

func TestNew(t *testing.T) {
	t.Parallel()

	httpserver.New(nil)
}

func TestNewWithAllOpts(t *testing.T) {
	t.Parallel()

	httpserver.New(nil,
		httpserver.WithAddr(""),
		httpserver.WithReadTimeout(0),
	)
}

func TestNotify(t *testing.T) {
	t.Parallel()

	srv := httpserver.New(nil)
	go srv.Run()

	require.NoError(t, srv.Shutdown(context.TODO()))
	assert.ErrorIs(t, <-srv.Notify(), http.ErrServerClosed)
}
