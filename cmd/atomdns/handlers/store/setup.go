package store

import (
	"context"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/tidwall/btree"
	"golang.org/x/sync/singleflight"
)

const (
	wakeup = 5 * time.Minute
	dump   = 15 * time.Second
)

var group singleflight.Group

func (s *Store) Setup(co *dnsserver.Controller) error {
	s.Tree = btree.NewBTreeG(Less)
	ctx, cancel := context.WithCancel(context.Background())
	co.Next()

	co.OnStartup(func() error {
		log.Info("Startup", "evict", wakeup)
		go func() {
			ticker := time.NewTicker(wakeup)
			tick2 := time.NewTicker(dump)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					group.Do("evict", func() (any, error) {
						s.Evict()
						return nil, nil
					})
				case <-tick2.C:
					s.Dump()
				case <-ctx.Done():
					return
				}
			}
		}()
		return nil
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "evict", wakeup)
		cancel()
		return nil
	})

	return nil
}
