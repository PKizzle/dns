package atom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/metrics"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/refuse"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/unpack"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

type ServerOption struct {
	Quiet         bool   // show no startup information
	Addr          string // address to run on
	Servers       int    // run this many servers
	MaxTCPQueries int    // when to cut a tcp connection
}

type Server struct {
	global  *global.Global
	servers []*dns.Server
	mux     *dns.ServeMux
	started chan error

	quiet bool
	addr  string
}

func (s *Server) Start() error {
	for i := range s.servers {
		go serve(s.started, s.servers[i], s.global)
	}
	// drain the channel, we either get a nil for success or otherwise an error _for each server_ started
	for range s.servers {
		err := <-s.started
		if err != nil {
			return err
		}
	}
	return nil
}

func serve(ch chan error, srv *dns.Server, global *global.Global) {
	if err := global.Startup(); err != nil {
		ch <- err
		return
	}

	if err := srv.ListenAndServe(); err != nil {
		ch <- err
		return
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.global.Shutdown(); err != nil {
		slog.Warn("Failed to run shutdown: " + err.Error())
	}
	for _, srv := range s.servers {
		srv.Shutdown(context.TODO())
	}
	return nil
}

// New returns a new server that has parsed the config in and r and applied the options.
func New(conf string, r io.Reader, options ServerOption) (*Server, error) {
	s := &Server{quiet: options.Quiet, addr: options.Addr, mux: dns.NewServeMux()}

	global, err := s.parse(conf, r)
	if err != nil {
		return nil, err
	}
	s.global = global

	s.servers = make([]*dns.Server, options.Servers*2) // *2=udp/tcp
	s.started = make(chan error, len(s.servers))
	for j := range s.servers {
		net := "tcp"
		if j < len(s.servers)/2 {
			net = "udp"
		}
		s.servers[j] = &dns.Server{
			Handler: s.mux, Net: net, Addr: options.Addr,
			ReuseAddr: true, ReusePort: true,
			MaxTCPQueries: options.MaxTCPQueries,
		}
		i := uint64(0)
		N := global.MetricsN
		s.servers[j].MsgInvalidFunc = func(_ *dns.Msg, _ error) {
			if N == 0 {
				return
			}
			if i%N == 0 {
				metrics.Dropped.Inc()
			}
			i++
		}
		s.servers[j].NotifyStartedFunc = func(_ context.Context) { s.started <- nil }
	}
	return s, nil
}

func (s *Server) parse(conf string, r io.Reader) (*global.Global, error) {
	blocks, err := conffile.Parse(conf, r)
	if err != nil {
		return nil, err
	}

	global := &global.Global{}
	for _, b := range blocks {
		if b.Keys != nil {
			continue
		}
		for _, dir := range b.Directives {
			d := conffile.NewDispenser(conf, nil, b.Tokens[dir])
			err := global.Setup(d)
			if err != nil {
				return global, fmt.Errorf("could not parse global config: %s", err)
			}
		}
		break
	}

	for _, b := range blocks {
		if b.Keys == nil {
			continue
		}
		// prepend unpack to start the chain
		hs := []handlers.Handler{new(unpack.Unpack)}
		names := []string{}
		for _, name := range b.Directives {
			names = append(names, name)
			newFn, ok := handlers.StringToHandler[name]
			if !ok {
				return global, fmt.Errorf("unknown handler: %s", name)
			}
			handler := newFn()
			if s, ok := handler.(handlers.Setupper); ok {
				co := &dnsserver.Controller{
					Dispenser: conffile.NewDispenser(conf, b.Keys, b.Tokens[name]),
					Global:    global,
				}
				err := s.Setup(co)
				if err != nil {
					return global, handler.Err(err)
				}
			}
			hs = append(hs, handler)
		}
		// append refuse as a guard
		hs = append(hs, new(refuse.Refuse))
		// for all keys (=zones) add this chain
		for _, k := range b.Keys {
			k = dnsutil.Fqdn(k)
			if !s.quiet {
				slog.Info(k, "handlers", strings.Join(names, ",")+",refuse")
			}
			s.mux.HandleFunc(k, handlers.Compile(hs))
		}
	}
	return global, nil
}

// When a server is started on the wildcard port, this method can be used to get the actual address and
// listening port. Note that with a wildcard port the servers will all run on a different port. For all
// returned address the first half are the UDP listening port, the other half is TCP.
func (s *Server) Addr() []string {
	addr := make([]string, len(s.servers))
	for i, srv := range s.servers {
		if x := srv.Listener; x != nil {
			addr[i] = x.Addr().String()
		}
		if x := srv.PacketConn; x != nil {
			addr[i] = x.LocalAddr().String()
		}
	}
	return addr
}

// NewTest returns a server suitable for testing. Use cancel to shutdown the server
// Use [server.Addr] to get the listening addresses. NewTest starts 2 servers, one on UDP and another on TCP.
func NewTest(config string) (*Server, func(), error) {
	options := ServerOption{Quiet: true, Addr: net.JoinHostPort("::", "0"), Servers: 1}
	s, err := New("test", strings.NewReader(config), options)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Start(); err != nil {
		return nil, nil, err
	}
	return s, func() { s.Shutdown(context.TODO()) }, nil
}
