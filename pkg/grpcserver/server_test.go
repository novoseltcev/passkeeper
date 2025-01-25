package grpcserver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/novoseltcev/passkeeper/pkg/grpcserver"
)

func TestNotify(t *testing.T) {
	t.Parallel()

	srv := grpcserver.New(":80")
	go srv.Run()

	require.NoError(t, srv.Shutdown())
	assert.ErrorIs(t, <-srv.Notify(), grpc.ErrServerStopped)
}

func TestListenError(t *testing.T) {
	t.Parallel()

	srv := grpcserver.New("unknown")
	go srv.Run()

	require.NoError(t, srv.Shutdown())
	assert.ErrorContains(t, <-srv.Notify(), "address unknown: ")
}

func TestGetServiceRegistrar(t *testing.T) {
	t.Parallel()

	srv := grpcserver.New(":80")

	assert.IsType(t, &grpc.Server{}, srv.GetServiceRegistrar())
}
