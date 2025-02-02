package httpserver

import "time"

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

// WithWriteTimeout sets timeout for writing response.
func WithWriteTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.server.WriteTimeout = timeout
	}
}
