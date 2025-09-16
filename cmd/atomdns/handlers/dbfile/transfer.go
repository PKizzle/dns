package dbfile

import (
	"context"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

// Transfer implements the transfer.Transfer interface.
func (d *Dbfile) TransferOut(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	w.Hijack()
	env := make(chan *dns.Envelope)
	c := dns.NewClient()
	var wg sync.WaitGroup

	wg.Go(func() {
		c.TransferOut(w, r, env)
		w.Close()
	})

	d.RLock()
	z := d.Zones[dns.Zone(ctx)]
	d.RUnlock()

	apex := z.Apex()
	z.Walk(func(n zone.Node) bool {
		env <- &dns.Envelope{Answer: n.RRs}
		return true
	})
	for _, rr := range apex.RRs {
		if s, ok := rr.(*dns.SOA); ok {
			env <- &dns.Envelope{Answer: []dns.RR{s}}
		}
	}
	close(env)

	return nil
}

func (d *Dbfile) TransferIn(ctx context.Context) error {
	return nil
}
