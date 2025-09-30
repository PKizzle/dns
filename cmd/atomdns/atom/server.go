package atom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

type Server struct {
	global  *global.Global
	servers []*dns.Server
	mux     *dns.ServeMux
	started chan error

	// Quiet startup
	Quiet bool
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
	slog.Info("Launched", "config", filepath.Base(s.global.Config), "origins", len(s.global.Registered))
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
		slog.Warn("Failed to run shutdown", slog.Any("error", err))
	}
	for _, srv := range s.servers {
		srv.Shutdown(context.TODO())
	}
	return nil
}

// New returns a new server that has parsed the config in and r.
func New(conf string, r io.Reader) (*Server, error) {
	s := &Server{mux: dns.NewServeMux()}

	global, err := s.parse(conf, r)
	if err != nil {
		return nil, err
	}
	s.global = global
	s.servers = make([]*dns.Server, global.Servers*2) // *2=udp/tcp
	s.started = make(chan error, len(s.servers))
	for j := range s.servers {
		net := "tcp"
		if j < len(s.servers)/2 {
			net = "udp"
		}
		s.servers[j] = &dns.Server{
			Handler: s.mux, Net: net, Addr: global.Addr,
			MaxTCPQueries: global.MaxTCPQueries,
			ReuseAddr:     true, ReusePort: true,
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

	global := &global.Global{
		Registered:    make(map[string]struct{}),
		Config:        conf,
		Root:          func() string { wd, _ := os.Getwd(); return wd }(),
		Addr:          "[::]:53",
		MaxTCPQueries: 128,
		Servers:       runtime.NumCPU() * 3,
	}
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
			k = dnsutil.Canonical(k)

			if _, ok := global.Registered[k]; ok {
				return global, fmt.Errorf("origin already registered: %s", k)
			}

			if !s.Quiet {
				slog.Info(k, "handlers", "unpack,"+strings.Join(names, ",")+",refuse")
			}
			s.mux.HandleFunc(k, handlers.Compile(hs))
			global.Registered[k] = struct{}{}
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
