package dnszone

import (
	"context"
	"sync"

	"codeberg.org/miekg/dns"
)

func TransferOut(z Interface, ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	w.Hijack()
	env := make(chan *dns.Envelope)
	c := dns.NewClient()
	var wg sync.WaitGroup

	wg.Go(func() {
		c.TransferOut(w, r, env)
		w.Close()
	})

	apex := z.Apex()
	z.Walk(func(n Node) bool {
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
