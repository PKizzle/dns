package atomhttp

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	reuse "codeberg.org/miekg/dns/cmd/atomdns/internal/reuse"
	"codeberg.org/miekg/dns/dnshttp"
)

// ServeHTTP implements the http.Handler and is the bridge between the HTTP and DNS worlds.
// It the request and converts to the DNS format, calls the handlers, converts it back and writes it to the client.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, err := dnshttp.Request(r)
	if err != nil {
		slog.Debug("Failed to convert http request", "server", "doh", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hw := dnshttp.NewResponseWriter(w, r, r.Context().Value(http.LocalAddrContextKey).(net.Addr))
	h.mux.ServeDNS(context.Background(), hw, m)
}

type Server struct {
	server   *http.Server
	Listener net.Listener
}

func Serve(ch chan error, s *Server, global *global.Global) {
	l, err := reuse.ListenTCP("tcp", s.server.Addr, true, true)
	if err != nil {
		ch <- err
		return
	}
	lt := l
	if global.TlsConfig != nil {
		lt = tls.NewListener(l, global.TlsConfig)
	}
	if global.TlsCertConfig != nil {
		tlsConfig := global.TlsCertConfig.TLSConfig()
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, []string{"h2", "http/1.1"}...)
		lt = tls.NewListener(l, tlsConfig)
	}
	go func() {
		if err := s.server.Serve(lt); err != nil {
			ch <- err
			return
		}
	}()
	s.Listener = lt
	ch <- nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Shutdown(ctx)
	return nil
}

func New(addr string, mux *dns.ServeMux) *Server {
	s := new(Server)
	h := newHandler(mux)
	logger := slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)
	s.server = &http.Server{Addr: addr, Handler: h, ErrorLog: logger}
	return s
}

type handler struct {
	mux *dns.ServeMux
}

func newHandler(mux *dns.ServeMux) *http.ServeMux {
	hmux := http.NewServeMux()
	handler := &handler{mux: mux}
	hmux.Handle("/dns-query", handler)
	return hmux
}
