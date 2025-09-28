package global

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

type Global struct {
	// Root
	Root string
	// Metrics
	MetricsN        uint64
	MetricsListener net.Listener
	// Health
	Lameduck       time.Duration
	HealthListener net.Listener
	// Pprof
	PprofListener net.Listener
	// Server
	Quiet         bool
	Addr          string
	MaxTCPQueries int
	Servers       int

	onceStartup  sync.Once
	onceShutdown sync.Once
	onStartup    []func() error // Functions to execute on startup
	onShutdown   []func() error // Function to execute on shutdown
}

func (g *Global) OnStartup(fn func() error)  { g.onStartup = append(g.onStartup, fn) }
func (g *Global) OnShutdown(fn func() error) { g.onShutdown = append(g.onShutdown, fn) }

func (g *Global) Startup() error {
	errs := []error{}
	wg := sync.WaitGroup{}
	g.onceStartup.Do(func() {
		slog.Debug("Startup functions", slog.Int("total", len(g.onStartup)))
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
		slog.Debug("Shutdown functions", slog.Int("total", len(g.onShutdown)))
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
