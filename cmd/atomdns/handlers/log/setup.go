package log

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

var (
	state     atomic.Bool
	startonce sync.Once
	shutonce  sync.Once
)

func (l *Log) Setup(co *dnsserver.Controller) error {
	state.Store(true)
	ctx, cancel := context.WithCancel(context.Background())

	startonce.Do(func() {
		co.OnStartup(func() error {
			_log.Info("Startup", "signal", "USR1")
			sigchan := make(chan os.Signal, 1)
			go func() {
				signal.Notify(sigchan, syscall.SIGUSR1)
				for {
					select {
					case <-sigchan:
						signal.Notify(sigchan, syscall.SIGUSR1)
						if state.Load() {
							_log.Info("Received signal, disabling query logging")
							state.Store(false)
						} else {
							_log.Info("Received signal, enabling query logging")
							state.Store(true)
						}
					case <-ctx.Done():
						return
					}
				}
			}()
			return nil
		})
	})

	shutonce.Do(func() {
		co.OnShutdown(func() error {
			_log.Info("Shutdown", "signal", "USR1")
			cancel()
			return nil
		})
	})

	return nil
}
