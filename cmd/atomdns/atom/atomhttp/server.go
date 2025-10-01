package atomhttp

import (
	"context"
	"net/http"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
)

type Server struct {
	server  *http.Server
	started chan error
	// timeouts 'n shit
}

func (s *Server) Start() error {
	go serve(s.started, s.server)

	for range 1 {
		err := <-s.started
		if err != nil {
			return err
		}
	}
	//	slog.Info("Launched", "config", filepath.Base(s.global.Config), "origins", len(s.global.Registered))
	return nil
}

func serve(ch chan error, srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil {
		ch <- err
		return
	}
	// tls
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Shutdown(ctx)
	return nil
}

func New(mux *dns.ServeMux, global *global.Global) (*Server, error) {
	s := new(Server)
	s.started = make(chan error, 1)
	s.server = new(http.Server)
	s.server.Addr = "[::]:8053"
	return s, nil
}
