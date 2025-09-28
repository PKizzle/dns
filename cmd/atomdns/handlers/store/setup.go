package store

import (
	"context"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/tidwall/btree"
)

const wakeup = 5 * time.Minute

func (s *Store) Setup(co *dnsserver.Controller) error {
	ctx, cancel := context.WithCancel(context.Background())
	for co.Next() {
	}
	s.Tree = btree.NewBTreeG(Less)

	co.OnStartup(func() error {
		log.Info("Startup", "evict", wakeup)
		ticker := time.NewTicker(wakeup)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:

			case <-ctx.Done():
				return nil
			}
		}
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "evict", wakeup)
		cancel()
		return nil
	})

	return nil
}
