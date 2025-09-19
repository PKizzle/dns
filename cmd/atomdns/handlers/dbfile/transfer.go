package dbfile

import (
	"context"
	"fmt"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

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

func (d *Dbfile) TransferIn(origin string) error {
	// save into temp file and then move this file over the dbfile path.
	c := dns.NewClient()
	m := dns.NewMsg(origin, dns.TypeAXFR)
	// compare SOA
	for _, ip := range d.From.IPs {
		env, err := c.TransferIn(context.TODO(), m, "tcp", ip)
		if err != nil {
			continue
		}
		for e := range env {
			if e.Error != nil {
				// ...
			}
			fmt.Printf("%v\n", e.Answer)
			// e.Answer kan be inserted into the a new zone
		}

		break
	}
	// do we want to save this on disk somewhere
	return nil
}
