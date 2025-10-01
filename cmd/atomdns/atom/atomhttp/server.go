package atomhttp

import (
	"context"
	"net"
	"net/http"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/reuse"
	"codeberg.org/miekg/dns/dnshttp"
)

type Server struct {
	server   *http.Server
	mux      *dns.ServeMux
	listener net.Listener
}

func Serve(ch chan error, s *Server) {
	l, err := reuse.ListenTCP("tcp", s.server.Addr, true, true)
	if err != nil {
		ch <- err
		return
	}

	go func() {
		if err := http.Serve(l, nil); err != nil {
			ch <- err
			return
		}
	}()
	ch <- nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Shutdown(ctx)
	return nil
}

func New(addr string, httpmux *http.ServeMux, mux *dns.ServeMux, global *global.Global) *Server {
	s := new(Server)
	s.mux = mux
	s.server = &http.Server{Addr: addr, Handler: httpmux}
	return s
}

// ServeHTTP is the handler that gets the HTTP request and converts to the dns format, calls the handlers
// converts it back and write it to the client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	println("hallo", r.URL.Path)
	m, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	println(m.String())

	hw := ResponseWriter{}

	s.mux.ServeDNS(context.Background(), hw, m)
}

type ResponseWriter struct {
	dns.ResponseWriter
}
