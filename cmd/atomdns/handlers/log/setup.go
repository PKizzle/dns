package log

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

var (
	state     atomic.Bool
	startonce sync.Once
	shutonce  sync.Once
)

func (l *Log) Setup(co *dnsserver.Controller) error {
	for co.NextBlock(0) {
		for co.NextLine() {
			if co.Val() == "}" {
				break
			}
			if !strings.Contains(co.Val(), "/") {
				return co.PropErr(fmt.Errorf("context key needs to have '/' %s", co.Val()))
			}
			if slices.Contains([]string{"ecs/addr", "id/id"}, co.Val()) {
				return co.PropErr(fmt.Errorf("default context key used: %s", co.Val()))
			}
			l.Contexts = append(l.Contexts, co.Val())
		}
	}

	state.Store(true)
	ctx, cancel := context.WithCancel(context.Background())

	co.OnStartup(func() error {
		startonce.Do(func() {
			_log().Info("Startup", "signal", "USR1")
			sigchan := make(chan os.Signal, 1)
			go func() {
				signal.Notify(sigchan, SIGUSR1)
				for {
					select {
					case <-sigchan:
						signal.Notify(sigchan, SIGUSR1)
						if state.Load() {
							_log().Info("Received signal, disabling query logging")
							state.Store(false)
						} else {
							_log().Info("Received signal, enabling query logging")
							state.Store(true)
						}
					case <-ctx.Done():
						return
					}
				}
			}()
		})
		return nil
	})

	co.OnShutdown(func() error {
		shutonce.Do(func() {
			_log().Info("Shutdown", "signal", "USR1")
			cancel()
		})
		return nil
	})

	co.OnReset(func() {
		startonce = sync.Once{}
		shutonce = sync.Once{}
	})

	return nil
}
