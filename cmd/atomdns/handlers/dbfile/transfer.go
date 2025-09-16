package dbfile

import (
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/coredns/coredns/plugin/file/tree"
)

// Transfer implements the transfer.Transfer interface.
func (d *Dbfile) TransferOut(ctx context.Context, w dns.ResponseWriter) error {
	w.Hijack()
	env := make(chan *dns.Envelope)
	c := dns.NewClient()
	var wg sync.WaitGroup

	wg.Go(func() {
		w.TransferOut(w, env)
		w.Close()
	}

		d.RLock()
		z := d.Zones[dns.Zone(ctx)]
		d.RUnlock()

	z.Walk(func(n zone.Node


		if serial != 0 && apex[0].(*dns.SOA).Serial == serial { // ixfr fallback, only send SOA
			ch <- []dns.RR{apex[0]}

			close(ch)
			return
		}

		ch <- apex
		z.Walk(func(e *tree.Elem, _ map[uint16][]dns.RR) error { ch <- e.All(); return nil })
		ch <- []dns.RR{apex[0]}

		close(ch)
	}()

	return nil
}

func (d *Dbfile) TransferIn(ctx context.Context) error {
	return nil
}
