package httpserver

import (
	"crypto/tls"
	"time"
)

type Option func(*Server)

// WithAddr sets address for server.
func WithAddr(addr string) Option {
	return func(s *Server) {
		s.server.Addr = addr
	}
}

// WithReadTimeout sets timeout for reading request.
func WithReadTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.server.ReadTimeout = timeout
	}
}

// WithTLS sets TLS configuration for server.
func WithTLS(cfg *tls.Config) Option {
	return func(s *Server) {
		s.server.TLSConfig = cfg
	}
}
