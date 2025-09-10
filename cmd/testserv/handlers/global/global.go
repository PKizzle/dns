package global

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
)

type Global struct {
	Root            string
	MetricsN        uint64
	MetricsListener net.Listener

	onceStartup  sync.Once
	onceShutdown sync.Once
	onStartup    []func() error // Functions to execute on startup
	onShutdown   []func() error // Function to execute on shutdown
}

func (g *Global) OnStartup(fn func() error)  { g.onStartup = append(g.onStartup, fn) }
func (g *Global) OnShutdown(fn func() error) { g.onShutdown = append(g.onShutdown, fn) }

func (g *Global) Startup() error {
	errs := []error{}
	g.onceStartup.Do(func() {
		slog.Debug(fmt.Sprintf("Running %d startup functions", len(g.onStartup)))
		for _, fn := range g.onStartup {
			if err := fn(); err != nil {
				errs = append(errs, err)
			}
		}
	})
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	return nil
}

func (g *Global) Shutdown() error {
	errs := []error{}
	g.onceShutdown.Do(func() {
		for _, fn := range g.onShutdown {
			slog.Debug(fmt.Sprintf("Running %d shutdown d functions", len(g.onStartup)))
			if err := fn(); err != nil {
				errs = append(errs, err)
			}
		}
	})
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	return nil
}
