package atomhttp

import (
	"context"
	"net"
	"net/http"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/dnshttp"
)

type Server struct {
	server *http.Server
	mux    *dns.ServeMux
}

func Serve(ch chan error, srv *Server) {
	l, err := net.Listen("tcp", ":8080")
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

func New(mux *dns.ServeMux, global *global.Global) *Server {
	s := new(Server)
	s.mux = mux
	s.server = new(http.Server)
	s.server.Addr = "[::]:8053" // reuse port 'n shit
	return s
}

// ServeHTTP is the handler that gets the HTTP request and converts to the dns format, calls the hanlders
// converts it back and write it to the client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mux.ServeDNS(context.Background(), w, msg)
}
