package global

import (
	"fmt"
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
		wg.Add(1)
		go func() {
			slog.Debug(fmt.Sprintf("Running %d startup functions", len(g.onStartup)))
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
		for _, fn := range g.onShutdown {
			wg.Add(1)
			go func() {
				slog.Debug(fmt.Sprintf("Running %d shutdown functions", len(g.onStartup)))
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
