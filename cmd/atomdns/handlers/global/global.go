package global

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

type Global struct {
	// Root
	Root string
	// Debug
	Debug bool
	// Metrics
	MetricsN        uint64
	MetricsListener net.Listener
	// Health
	Lameduck       time.Duration
	HealthListener net.Listener
	// Pprof
	PprofListener net.Listener
	// dns
	Quiet         bool
	Addr          string
	MaxTCPQueries int
	Servers       int
	// doh
	HttpAddr    string
	HttpServers int
	// tls
	TlsConfig     *tls.Config // manual
	TlsCertConfig *certmagic.Config
	TlsIPs        []string // lets-encrypt, IP to get certs for
	TlsContact    string   // lets-encrypt
	TlsPath       string   // lets-encrypt

	onceStartup  sync.Once
	onceShutdown sync.Once
	onStartup    []func() error // Functions to execute on startup
	onShutdown   []func() error // Function to execute on shutdown

	Config     string              // path to config file
	Registered map[string]struct{} // registered zones
}

func (g *Global) OnStartup(fn func() error)  { g.onStartup = append(g.onStartup, fn) }
func (g *Global) OnShutdown(fn func() error) { g.onShutdown = append(g.onShutdown, fn) }

func (g *Global) Startup() error {
	errs := []error{}
	wg := sync.WaitGroup{}
	g.onceStartup.Do(func() {
		slog.Info("Startup functions", slog.Int("total", len(g.onStartup)))
		wg.Add(1)
		go func() {
			for _, fn := range g.onStartup {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
			}
			wg.Done()
		}()
	})
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	return nil
}

func (g *Global) Shutdown() error {
	errs := []error{}
	wg := sync.WaitGroup{}
	g.onceShutdown.Do(func() {
		slog.Info("Shutdown functions", slog.Int("total", len(g.onShutdown)))
		for _, fn := range g.onShutdown {
			wg.Add(1)
			go func() {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
				wg.Done()
			}()
		}
	})
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	return nil
}
