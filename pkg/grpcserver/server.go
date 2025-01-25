// Package httpserver implements HTTP server.
package grpcserver

import (
	"net"

	"google.golang.org/grpc"
)

// Server represents HTTP Server.
type Server struct {
	server *grpc.Server
	addr   string
	notify chan error
}

func New(addr string, opts ...grpc.ServerOption) *Server {
	return &Server{
		addr:   addr,
		server: grpc.NewServer(opts...),
		notify: make(chan error, 1),
	}
}

func (srv *Server) Notify() <-chan error {
	return srv.notify
}

func (srv *Server) GetServiceRegistrar() grpc.ServiceRegistrar { // nolint: ireturn
	return srv.server
}

func (srv *Server) Shutdown() error {
	srv.server.GracefulStop()

	return nil
}

func (srv *Server) Run() {
	srv.notify <- srv.listenAndServe()
	close(srv.notify)
}

func (srv *Server) listenAndServe() error {
	ln, err := net.Listen("tcp", srv.addr)
	if err != nil {
		return err
	}

	return srv.server.Serve(ln)
}
