// Package httpserver implements HTTP server.
package httpserver

import (
	"context"
	"net/http"
	"time"
)

const (
	defaultReadTimeout  = 5 * time.Second
	defaultWriteTimeout = 5 * time.Second
	defaultAddr         = ":80"
)

// Server represents HTTP server.
type Server struct {
	server *http.Server
	notify chan error
}

// New creates new server and start listening.
func New(handler http.Handler, opts ...Option) *Server {
	srv := &Server{
		server: &http.Server{
			Handler:      handler,
			ReadTimeout:  defaultReadTimeout,
			WriteTimeout: defaultWriteTimeout,
			Addr:         defaultAddr,
		},
		notify: make(chan error, 1),
	}

	for _, opt := range opts {
		opt(srv)
	}

	return srv
}

// Notify returns a channel that will be closed when server is stopped.
func (srv *Server) Notify() <-chan error {
	return srv.notify
}

func (srv *Server) Shutdown(ctx context.Context) error {
	return srv.server.Shutdown(ctx)
}

func (srv *Server) Run() {
	srv.notify <- srv.server.ListenAndServe()
	close(srv.notify)
}
