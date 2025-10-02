package atomhttp

import (
	"context"
	"net"
	"net/http"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/reuse"
	"codeberg.org/miekg/dns/dnshttp"
)

type Server struct {
	server   *http.Server
	Listener net.Listener
}

func Serve(ch chan error, s *Server) {
	l, err := reuse.ListenTCP("tcp", s.server.Addr, true, true)
	if err != nil {
		ch <- err
		return
	}

	go func() {
		// TLS
		if err := s.server.Serve(l); err != nil {
			ch <- err
			return
		}
	}()
	s.Listener = l
	ch <- nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Shutdown(ctx)
	return nil
}

func New(addr string, mux *http.ServeMux) *Server {
	s := new(Server)
	s.server = &http.Server{Addr: addr, Handler: mux}
	return s
}

// Handler is the HTTP handler that gets the request and converts to the DNS format, calls the handlers,
// converts it back and writes it to the client.
type Handler struct {
	mux *dns.ServeMux
}

func NewMux(mux *dns.ServeMux) *http.ServeMux {
	hmux := http.NewServeMux()
	handler := &Handler{mux: mux}
	hmux.Handle("/dns-query", handler)
	return hmux
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	println("hallo", r.URL.Path)
	m, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	println(m.String())

	hw := ResponseWriter{}

	h.mux.ServeDNS(context.Background(), hw, m)
}

type ResponseWriter struct {
	dns.ResponseWriter
}
