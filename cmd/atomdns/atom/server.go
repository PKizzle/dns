package atom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

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
	ReuseAddr     bool   // allow reuse address
	ReusePort     bool   // allow reuse port
	MaxTCPQueries int    // when to cut a tcp connection
}

type Server struct {
	global  *global.Global
	servers []*dns.Server
	mux     *dns.ServeMux

	quiet bool
	addr  string
}

func (s *Server) Start() error {
	// figure out a nice way to propagate errors, error.WaitGroup could be used, but in the happy path
	// ListenAndServe does not return anything, so it will wait until the end of time?? Wait for single
	// error channel, and if nothing continue?
	wg := sync.WaitGroup{}
	for _, srv := range s.servers {
		wg.Add(1)
		go serve(srv, s.global)
		wg.Done()
	}
	wg.Wait()
	return nil
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

func serve(srv *dns.Server, global *global.Global) {
	if err := global.Startup(); err != nil {
		slog.Error("Failed to run startup: " + err.Error())
		os.Exit(1)
	}

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("Failed to start: " + err.Error())
		os.Exit(1)
	}
}

func New(conf string, r io.Reader, options ServerOption) (*Server, error) {
	s := &Server{quiet: options.Quiet, addr: options.Addr, mux: dns.NewServeMux()}
	global, err := s.parse(conf, r)
	if err != nil {
		return nil, err
	}

	s.servers = make([]*dns.Server, options.Servers*2) // *2=udp/tcp
	for j := range s.servers {
		net := "tcp"
		if j < len(s.servers)/2 {
			net = "udp"
		}
		s.servers[j] = &dns.Server{
			Handler: s.mux, Net: net, Addr: options.Addr,
			ReuseAddr: options.ReuseAddr, ReusePort: options.ReusePort,
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
				slog.Info(k, "handlers", strings.Join(names, ","))
			}
			s.mux.HandleFunc(k, handlers.Compile(hs))
		}
	}
	return global, nil
}
