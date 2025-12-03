package subnet

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

type Subnet struct{}

func (s *Subnet) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for _, o := range r.Pseudo {
			if ecs, ok := o.(*dns.SUBNET); ok {
				ctx = dnsctx.WithValue(ctx, s.Key()+"/address", ecs.Address.String())
				break
			}
		}
		println("caclling")
		next.ServeDNS(ctx, w, r)
	})
}
