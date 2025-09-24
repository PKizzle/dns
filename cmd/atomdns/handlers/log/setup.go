package log

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (l *Log) Setup(co *dnsserver.Controller) error {
	state.Store(true)
	ctx, cancel := context.WithCancel(context.Background())

	co.OnStartup(func() error {
		_log.Info("Startup", "signal", syscall.SIGUSR1)
		sigchan := make(chan os.Signal, 1)
		go func() {
			signal.Notify(sigchan, syscall.SIGUSR1)
			for {
				select {
				case <-sigchan:
					signal.Notify(sigchan, syscall.SIGUSR1)
					if state.Load() {
						_log.Info("Disabling query logging")
						state.Store(false)
					} else {
						_log.Info("Enabling query logging")
						state.Store(true)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		return nil
	})

	co.OnShutdown(func() error {
		_log.Info("Shutdown", "signal", syscall.SIGUSR1)
		cancel()
		return nil
	})

	return nil
}
